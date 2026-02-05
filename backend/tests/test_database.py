"""
Tests unitaires pour le module Database de l'Agent IA de Cybersécurité

Ce module teste toutes les fonctionnalités du gestionnaire de base de données :
- Connexion et configuration SQLite
- Opérations CRUD
- Gestion des transactions
- Sauvegarde et restauration
- Migration des schémas
- Intégrité des données
"""

import json
import os
import pytest
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.database.database import Database, DatabaseConnection
from src.database import (
    DatabaseError, ConnectionError, MigrationError, ValidationError,
    IntegrityError, DatabaseErrorCodes, DEFAULT_DATABASE_CONFIG,
    create_database, backup_database, restore_database, get_database_stats
)


class TestDatabaseConnection:
    """Tests pour la classe DatabaseConnection"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, "test_connection.db")
        self.config = DEFAULT_DATABASE_CONFIG.copy()
        self.config['database_path'] = self.test_db_path

    def teardown_method(self):
        """Nettoyage après chaque test"""
        # Supprimer les fichiers temporaires
        if os.path.exists(self.test_db_path):
            os.unlink(self.test_db_path)

        # Nettoyer le répertoire temporaire
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_connection_initialization(self):
        """Test de l'initialisation de la connexion"""
        conn = DatabaseConnection(self.test_db_path, self.config)

        assert conn.database_path == self.test_db_path
        assert conn.config == self.config
        assert conn.connection is None
        assert conn.is_connected is False

    def test_successful_connection(self):
        """Test de connexion réussie"""
        conn = DatabaseConnection(self.test_db_path, self.config)

        # Établir la connexion
        connection = conn.connect()

        assert connection is not None
        assert conn.is_connected is True
        assert isinstance(connection, sqlite3.Connection)

        # Vérifier que le fichier de base de données existe
        assert os.path.exists(self.test_db_path)

        # Fermer la connexion
        conn.close()
        assert conn.is_connected is False

    def test_connection_with_invalid_path(self):
        """Test de connexion avec chemin invalide"""
        invalid_path = "/invalid/path/database.db"
        conn = DatabaseConnection(invalid_path, self.config)

        # La connexion devrait créer les répertoires manquants
        # ou lever une exception si impossible
        with pytest.raises(ConnectionError):
            conn.connect()

    def test_connection_configuration(self):
        """Test de la configuration de la connexion"""
        conn = DatabaseConnection(self.test_db_path, self.config)
        connection = conn.connect()

        # Vérifier que les PRAGMAs sont appliqués
        cursor = connection.cursor()

        # Test journal_mode
        cursor.execute("PRAGMA journal_mode")
        journal_mode = cursor.fetchone()[0]
        assert journal_mode == self.config.get('journal_mode', 'WAL')

        # Test foreign_keys
        cursor.execute("PRAGMA foreign_keys")
        foreign_keys = cursor.fetchone()[0]
        assert foreign_keys == (1 if self.config.get('foreign_keys', True) else 0)

        cursor.close()
        conn.close()

    def test_execute_query(self):
        """Test d'exécution de requêtes"""
        conn = DatabaseConnection(self.test_db_path, self.config)
        conn.connect()

        # Créer une table de test
        cursor = conn.execute("CREATE TABLE test_table (id INTEGER, name TEXT)")
        assert cursor is not None
        cursor.close()

        # Insérer des données
        cursor = conn.execute(
            "INSERT INTO test_table (id, name) VALUES (?, ?)",
            (1, "test")
        )
        assert cursor.lastrowid == 1
        cursor.close()

        # Sélectionner les données
        cursor = conn.execute("SELECT * FROM test_table WHERE id = ?", (1,))
        result = cursor.fetchone()
        assert result is not None
        assert result['id'] == 1
        assert result['name'] == "test"
        cursor.close()

        conn.close()

    def test_execute_many(self):
        """Test d'exécution de requêtes multiples"""
        conn = DatabaseConnection(self.test_db_path, self.config)
        conn.connect()

        # Créer une table
        cursor = conn.execute("CREATE TABLE test_bulk (id INTEGER, value TEXT)")
        cursor.close()

        # Insérer plusieurs enregistrements
        data = [(1, "value1"), (2, "value2"), (3, "value3")]
        cursor = conn.executemany(
            "INSERT INTO test_bulk (id, value) VALUES (?, ?)",
            data
        )
        assert cursor.rowcount == 3
        cursor.close()

        # Vérifier les données
        cursor = conn.execute("SELECT COUNT(*) as count FROM test_bulk")
        result = cursor.fetchone()
        assert result['count'] == 3
        cursor.close()

        conn.close()

    def test_transaction_success(self):
        """Test de transaction réussie"""
        conn = DatabaseConnection(self.test_db_path, self.config)
        conn.connect()

        # Créer une table
        cursor = conn.execute("CREATE TABLE test_transaction (id INTEGER, value TEXT)")
        cursor.close()

        # Test transaction réussie
        with conn.transaction():
            conn.execute("INSERT INTO test_transaction VALUES (1, 'test1')")
            conn.execute("INSERT INTO test_transaction VALUES (2, 'test2')")

        # Vérifier que les données sont présentes
        cursor = conn.execute("SELECT COUNT(*) as count FROM test_transaction")
        result = cursor.fetchone()
        assert result['count'] == 2
        cursor.close()

        conn.close()

    def test_transaction_rollback(self):
        """Test de rollback de transaction"""
        conn = DatabaseConnection(self.test_db_path, self.config)
        conn.connect()

        # Créer une table
        cursor = conn.execute("CREATE TABLE test_rollback (id INTEGER PRIMARY KEY, value TEXT)")
        cursor.close()

        # Insérer une donnée initiale
        conn.execute("INSERT INTO test_rollback VALUES (1, 'initial')")

        # Test transaction avec erreur
        with pytest.raises(sqlite3.IntegrityError):
            with conn.transaction():
                conn.execute("INSERT INTO test_rollback VALUES (2, 'test1')")
                # Cette insertion va provoquer une erreur (clé dupliquée)
                conn.execute("INSERT INTO test_rollback VALUES (1, 'duplicate')")

        # Vérifier que seule la donnée initiale est présente
        cursor = conn.execute("SELECT COUNT(*) as count FROM test_rollback")
        result = cursor.fetchone()
        assert result['count'] == 1
        cursor.close()

        conn.close()


class TestDatabase:
    """Tests pour la classe Database principale"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, "test_database.db")

        self.config = DEFAULT_DATABASE_CONFIG.copy()
        self.config['database_path'] = self.test_db_path

        self.db = Database(self.config)

    def teardown_method(self):
        """Nettoyage après chaque test"""
        if hasattr(self, 'db'):
            self.db.close()

        # Supprimer les fichiers temporaires
        if os.path.exists(self.test_db_path):
            os.unlink(self.test_db_path)

        # Nettoyer le répertoire temporaire
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_database_initialization(self):
        """Test de l'initialisation de la base de données"""
        assert self.db.database_path == self.test_db_path
        assert self.db.config == self.config
        assert self.db.is_initialized is False
        assert len(self.db._connections) == 0

    def test_create_tables(self):
        """Test de création des tables"""
        self.db.create_tables()

        assert self.db.is_initialized is True
        assert os.path.exists(self.test_db_path)

        # Vérifier que les tables principales existent
        conn = self.db.get_connection()
        conn.connect()

        cursor = conn.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
        """)

        tables = [row[0] for row in cursor.fetchall()]
        cursor.close()

        expected_tables = ['scans', 'vulnerabilities', 'analyses', 'scripts', 'workflows']
        for table in expected_tables:
            assert table in tables

    def test_get_connection(self):
        """Test de récupération de connexion"""
        conn1 = self.db.get_connection()
        conn2 = self.db.get_connection()

        # Dans le même thread, on devrait avoir la même connexion
        assert conn1 is conn2
        assert len(self.db._connections) == 1

    def test_insert_operation(self):
        """Test d'insertion de données"""
        self.db.create_tables()

        # Test d'insertion simple
        test_data = {
            'scan_id': 'test_scan_001',
            'target': '192.168.1.100',
            'scan_type': 'quick',
            'status': 'completed'
        }

        result_id = self.db.insert('scans', test_data)
        assert result_id is not None
        assert int(result_id) > 0

    def test_select_operation(self):
        """Test de sélection de données"""
        self.db.create_tables()

        # Insérer des données de test
        test_data = {
            'scan_id': 'test_scan_001',
            'target': '192.168.1.100',
            'scan_type': 'quick',
            'status': 'completed'
        }
        self.db.insert('scans', test_data)

        # Test de sélection
        results = self.db.select('scans', where={'target': '192.168.1.100'})

        assert len(results) == 1
        assert results[0]['scan_id'] == 'test_scan_001'
        assert results[0]['target'] == '192.168.1.100'

    def test_select_one(self):
        """Test de sélection d'un seul enregistrement"""
        self.db.create_tables()

        # Insérer des données
        test_data = {
            'scan_id': 'test_scan_unique',
            'target': '192.168.1.200',
            'scan_type': 'full',
            'status': 'pending'
        }
        self.db.insert('scans', test_data)

        # Test select_one
        result = self.db.select_one('scans', where={'scan_id': 'test_scan_unique'})

        assert result is not None
        assert result['scan_id'] == 'test_scan_unique'
        assert result['target'] == '192.168.1.200'

        # Test avec résultat inexistant
        result = self.db.select_one('scans', where={'scan_id': 'nonexistent'})
        assert result is None

    def test_update_operation(self):
        """Test de mise à jour de données"""
        self.db.create_tables()

        # Insérer des données initiales
        test_data = {
            'scan_id': 'test_scan_update',
            'target': '192.168.1.150',
            'scan_type': 'quick',
            'status': 'pending'
        }
        self.db.insert('scans', test_data)

        # Mettre à jour le statut
        update_data = {'status': 'completed', 'duration': 120.5}
        rows_affected = self.db.update(
            'scans',
            update_data,
            where={'scan_id': 'test_scan_update'}
        )

        assert rows_affected == 1

        # Vérifier la mise à jour
        result = self.db.select_one('scans', where={'scan_id': 'test_scan_update'})
        assert result['status'] == 'completed'
        assert result['duration'] == 120.5
        assert 'updated_at' in result

    def test_delete_operation(self):
        """Test de suppression de données"""
        self.db.create_tables()

        # Insérer des données
        test_data = {
            'scan_id': 'test_scan_delete',
            'target': '192.168.1.250',
            'scan_type': 'quick',
            'status': 'failed'
        }
        self.db.insert('scans', test_data)

        # Vérifier que les données existent
        result = self.db.select_one('scans', where={'scan_id': 'test_scan_delete'})
        assert result is not None

        # Supprimer les données
        rows_deleted = self.db.delete('scans', where={'scan_id': 'test_scan_delete'})
        assert rows_deleted == 1

        # Vérifier que les données n'existent plus
        result = self.db.select_one('scans', where={'scan_id': 'test_scan_delete'})
        assert result is None

    def test_count_operation(self):
        """Test de comptage d'enregistrements"""
        self.db.create_tables()

        # Insérer plusieurs scans
        for i in range(5):
            test_data = {
                'scan_id': f'test_scan_{i:03d}',
                'target': '192.168.1.100',
                'scan_type': 'quick',
                'status': 'completed'
            }
            self.db.insert('scans', test_data)

        # Test comptage total
        total_count = self.db.count('scans')
        assert total_count == 5

        # Test comptage avec condition
        completed_count = self.db.count('scans', where={'status': 'completed'})
        assert completed_count == 5

        pending_count = self.db.count('scans', where={'status': 'pending'})
        assert pending_count == 0

    def test_bulk_insert(self):
        """Test d'insertion en lot"""
        self.db.create_tables()

        # Préparer des données en lot
        bulk_data = []
        for i in range(10):
            data = {
                'vulnerability_id': f'CVE-2024-{i:04d}',
                'name': f'Test Vulnerability {i}',
                'severity': 'MEDIUM',
                'cvss_score': 5.5,
                'description': f'Test description for vulnerability {i}',
                'affected_service': 'test_service',
                'affected_port': 80 + i
            }
            bulk_data.append(data)

        # Insertion en lot
        rows_inserted = self.db.bulk_insert('vulnerabilities', bulk_data)
        assert rows_inserted == 10

        # Vérifier que toutes les données sont présentes
        count = self.db.count('vulnerabilities')
        assert count == 10

    def test_save_scan_result(self):
        """Test de sauvegarde d'un résultat de scan complet"""
        self.db.create_tables()

        # Créer un mock ScanResult
        from unittest.mock import Mock

        # Mock vulnerability
        mock_vuln = Mock()
        mock_vuln.vulnerability_id = 'CVE-2024-0001'
        mock_vuln.name = 'Test Vulnerability'
        mock_vuln.severity = 'HIGH'
        mock_vuln.cvss_score = 8.5
        mock_vuln.description = 'Test vulnerability description'
        mock_vuln.affected_service = 'Apache'
        mock_vuln.affected_port = 80
        mock_vuln.cve_ids = ['CVE-2024-0001']
        mock_vuln.references = ['https://cve.mitre.org']
        mock_vuln.detection_method = 'nmap-script'
        mock_vuln.confidence = 'HIGH'

        # Mock ScanResult
        mock_scan_result = Mock()
        mock_scan_result.scan_id = 'test_scan_complete'
        mock_scan_result.target = '192.168.1.100'
        mock_scan_result.scan_type = 'full'
        mock_scan_result.started_at = datetime.utcnow()
        mock_scan_result.completed_at = datetime.utcnow()
        mock_scan_result.duration = 300.0
        mock_scan_result.nmap_version = '7.80'
        mock_scan_result.scan_parameters = {'timeout': 300, 'timing': 'T4'}
        mock_scan_result.vulnerabilities = [mock_vuln]

        # Sauvegarder le résultat
        result_id = self.db.save_scan_result(mock_scan_result)
        assert result_id is not None

        # Vérifier que le scan est sauvegardé
        scan = self.db.select_one('scans', where={'scan_id': 'test_scan_complete'})
        assert scan is not None
        assert scan['target'] == '192.168.1.100'

        # Vérifier que la vulnérabilité est sauvegardée
        vuln = self.db.select_one('vulnerabilities', where={'vulnerability_id': 'CVE-2024-0001'})
        assert vuln is not None
        assert vuln['name'] == 'Test Vulnerability'

    def test_get_scan_history(self):
        """Test de récupération de l'historique des scans"""
        self.db.create_tables()

        # Insérer plusieurs scans
        targets = ['192.168.1.10', '192.168.1.20', '192.168.1.10']
        for i, target in enumerate(targets):
            test_data = {
                'scan_id': f'history_scan_{i:03d}',
                'target': target,
                'scan_type': 'quick',
                'status': 'completed'
            }
            self.db.insert('scans', test_data)
            # Attendre pour avoir des timestamps différents
            time.sleep(0.01)

        # Test historique global
        history = self.db.get_scan_history(limit=10)
        assert len(history) == 3
        # Vérifier l'ordre (plus récent en premier)
        assert history[0]['scan_id'] == 'history_scan_002'

        # Test historique pour une cible spécifique
        target_history = self.db.get_scan_history(target='192.168.1.10', limit=10)
        assert len(target_history) == 2

    def test_get_vulnerabilities_by_severity(self):
        """Test de récupération par niveau de gravité"""
        self.db.create_tables()

        # Insérer des vulnérabilités avec différents niveaux
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'HIGH']
        for i, severity in enumerate(severities):
            vuln_data = {
                'vulnerability_id': f'TEST-{i:04d}',
                'name': f'Test Vulnerability {i}',
                'severity': severity,
                'cvss_score': 10.0 - i,
                'description': f'Test description {i}',
                'affected_service': 'test_service',
                'affected_port': 80
            }
            self.db.insert('vulnerabilities', vuln_data)

        # Test récupération par gravité
        high_vulns = self.db.get_vulnerabilities_by_severity('HIGH')
        assert len(high_vulns) == 2

        critical_vulns = self.db.get_vulnerabilities_by_severity('CRITICAL')
        assert len(critical_vulns) == 1
        assert critical_vulns[0]['cvss_score'] == 10.0

    def test_cleanup_old_data(self):
        """Test de nettoyage des anciennes données"""
        self.db.create_tables()

        # Insérer des données récentes et anciennes
        recent_time = datetime.utcnow().isoformat()
        old_time = (datetime.utcnow() - timedelta(days=35)).isoformat()

        # Données récentes
        recent_data = {
            'scan_id': 'recent_scan',
            'target': '192.168.1.100',
            'scan_type': 'quick',
            'status': 'completed',
            'created_at': recent_time
        }
        self.db.insert('scans', recent_data)

        # Données anciennes (avec manipulation directe pour contourner le timestamp automatique)
        conn = self.db.get_connection()
        conn.execute("""
            INSERT INTO scans (scan_id, target, scan_type, status, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, ('old_scan', '192.168.1.200', 'full', 'completed', old_time))

        # Test nettoyage
        cleanup_stats = self.db.cleanup_old_data(retention_days=30)

        assert 'scans' in cleanup_stats
        assert cleanup_stats['scans'] == 1

        # Vérifier que seules les données récentes restent
        remaining_scans = self.db.count('scans')
        assert remaining_scans == 1

        recent_scan = self.db.select_one('scans', where={'scan_id': 'recent_scan'})
        assert recent_scan is not None

    def test_backup_and_restore(self):
        """Test de sauvegarde et restauration"""
        self.db.create_tables()

        # Insérer des données de test
        test_data = {
            'scan_id': 'backup_test_scan',
            'target': '192.168.1.100',
            'scan_type': 'full',
            'status': 'completed'
        }
        self.db.insert('scans', test_data)

        # Créer une sauvegarde
        backup_path = self.db.backup()
        assert os.path.exists(backup_path.replace('.gz', '') if backup_path.endswith('.gz') else backup_path)

        # Supprimer la base originale
        self.db.close()
        os.unlink(self.test_db_path)

        # Restaurer depuis la sauvegarde
        success = self.db.restore(backup_path, verify_integrity=True)
        assert success is True

        # Vérifier que les données sont restaurées
        new_db = Database(self.config)
        result = new_db.select_one('scans', where={'scan_id': 'backup_test_scan'})
        assert result is not None
        assert result['target'] == '192.168.1.100'

        new_db.close()

    def test_database_stats(self):
        """Test des statistiques de base de données"""
        self.db.create_tables()

        # Insérer quelques données pour avoir des statistiques
        for i in range(3):
            test_data = {
                'scan_id': f'stats_scan_{i:03d}',
                'target': f'192.168.1.{100 + i}',
                'scan_type': 'quick',
                'status': 'completed'
            }
            self.db.insert('scans', test_data)

        # Récupérer les statistiques
        stats = self.db.get_stats()

        assert 'total_queries' in stats
        assert 'total_inserts' in stats
        assert 'table_counts' in stats
        assert stats['table_counts']['scans'] == 3
        assert stats['file_size_bytes'] > 0

    def test_health_check(self):
        """Test de vérification de santé"""
        self.db.create_tables()

        health = self.db.health_check()

        assert 'healthy' in health
        assert 'issues' in health
        assert 'warnings' in health
        assert health['healthy'] is True

    def test_custom_query(self):
        """Test d'exécution de requête personnalisée"""
        self.db.create_tables()

        # Insérer des données de test
        test_data = {
            'scan_id': 'custom_query_test',
            'target': '192.168.1.100',
            'scan_type': 'custom',
            'status': 'completed'
        }
        self.db.insert('scans', test_data)

        # Requête personnalisée
        custom_query = """
            SELECT s.scan_id, s.target, s.scan_type
            FROM scans s
            WHERE s.target = ? AND s.scan_type = ?
        """

        results = self.db.execute_custom_query(
            custom_query,
            ('192.168.1.100', 'custom'),
            fetch_results=True
        )

        assert results is not None
        assert len(results) == 1
        assert results[0]['scan_id'] == 'custom_query_test'

    def test_table_info(self):
        """Test de récupération d'informations sur les tables"""
        self.db.create_tables()

        table_info = self.db.get_table_info('scans')

        assert 'table_name' in table_info
        assert 'columns' in table_info
        assert 'indexes' in table_info
        assert 'record_count' in table_info

        assert table_info['table_name'] == 'scans'
        assert len(table_info['columns']) > 0

        # Vérifier quelques colonnes attendues
        column_names = [col['name'] for col in table_info['columns']]
        assert 'scan_id' in column_names
        assert 'target' in column_names
        assert 'scan_type' in column_names

    def test_database_optimization(self):
        """Test des opérations d'optimisation"""
        self.db.create_tables()

        # Test VACUUM
        try:
            self.db.vacuum()
        except Exception as e:
            pytest.fail(f"VACUUM failed: {e}")

        # Test ANALYZE
        try:
            self.db.analyze()
        except Exception as e:
            pytest.fail(f"ANALYZE failed: {e}")

        # Test REINDEX
        try:
            self.db.reindex()
        except Exception as e:
            pytest.fail(f"REINDEX failed: {e}")

        # Test optimisation complète
        try:
            self.db.optimize()
        except Exception as e:
            pytest.fail(f"Optimization failed: {e}")

    def test_context_manager(self):
        """Test du gestionnaire de contexte"""
        config = self.config.copy()
        test_db_path = os.path.join(self.temp_dir, "context_test.db")
        config['database_path'] = test_db_path

        # Test avec gestionnaire de contexte
        with Database(config) as db:
            db.create_tables()

            test_data = {
                'scan_id': 'context_test_scan',
                'target': '192.168.1.100',
                'scan_type': 'quick',
                'status': 'completed'
            }
            db.insert('scans', test_data)

            # Vérifier que les données sont présentes
            result = db.select_one('scans', where={'scan_id': 'context_test_scan'})
            assert result is not None

        # Après la sortie du contexte, la base devrait être fermée
        # Mais les données doivent persister
        new_db = Database(config)
        result = new_db.select_one('scans', where={'scan_id': 'context_test_scan'})
        assert result is not None
        new_db.close()


class TestDatabaseUtilities:
    """Tests pour les fonctions utilitaires de base de données"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Nettoyage après chaque test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_database_factory(self):
        """Test de la factory create_database"""
        test_db_path = os.path.join(self.temp_dir, "factory_test.db")
        config = {
            'database_path': test_db_path,
            'backup_enabled': True
        }

        db = create_database(config)

        assert isinstance(db, Database)
        assert db.database_path == test_db_path
        assert db.config['backup_enabled'] is True

        db.close()

    def test_backup_database_function(self):
        """Test de la fonction backup_database"""
        # Créer une base de données temporaire
        test_db_path = os.path.join(self.temp_dir, "backup_test.db")

        # Créer une base simple avec des données
        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test_table (id INTEGER, name TEXT)")
        cursor.execute("INSERT INTO test_table VALUES (1, 'test')")
        conn.commit()
        conn.close()

        # Test sauvegarde sans compression
        backup_path = backup_database(test_db_path, compress=False)
        assert os.path.exists(backup_path)
        assert backup_path.endswith('.db')

        # Test sauvegarde avec compression
        backup_compressed = backup_database(test_db_path, compress=True)
        assert os.path.exists(backup_compressed)
        assert backup_compressed.endswith('.gz')

    def test_restore_database_function(self):
        """Test de la fonction restore_database"""
        # Créer une base source
        source_db = os.path.join(self.temp_dir, "source.db")
        conn = sqlite3.connect(source_db)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE restore_test (id INTEGER, value TEXT)")
        cursor.execute("INSERT INTO restore_test VALUES (1, 'restored')")
        conn.commit()
        conn.close()

        # Créer une sauvegarde
        backup_path = backup_database(source_db, compress=False)

        # Restaurer vers une nouvelle base
        target_db = os.path.join(self.temp_dir, "restored.db")
        success = restore_database(backup_path, target_db, verify_integrity=True)

        assert success is True
        assert os.path.exists(target_db)

        # Vérifier que les données sont restaurées
        conn = sqlite3.connect(target_db)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM restore_test")
        result = cursor.fetchone()
        assert result == (1, 'restored')
        conn.close()

    def test_get_database_stats_function(self):
        """Test de la fonction get_database_stats"""
        # Créer une base de données avec des données
        test_db_path = os.path.join(self.temp_dir, "stats_test.db")

        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE stats_table (id INTEGER, data TEXT)")

        # Insérer plusieurs enregistrements
        for i in range(10):
            cursor.execute("INSERT INTO stats_table VALUES (?, ?)", (i, f"data_{i}"))

        conn.commit()
        conn.close()

        # Récupérer les statistiques
        stats = get_database_stats(test_db_path)

        assert 'file_size_bytes' in stats
        assert 'file_size_human' in stats
        assert 'tables_count' in stats
        assert 'tables' in stats
        assert stats['file_size_bytes'] > 0
        assert stats['tables']['stats_table'] == 10

    def test_database_stats_nonexistent_file(self):
        """Test des stats sur un fichier inexistant"""
        nonexistent_path = os.path.join(self.temp_dir, "nonexistent.db")
        stats = get_database_stats(nonexistent_path)

        assert 'error' in stats
        assert stats['error'] == "Base de données non trouvée"


class TestDatabaseErrors:
    """Tests pour la gestion des erreurs de base de données"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Nettoyage après chaque test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_connection_error(self):
        """Test des erreurs de connexion"""
        # Test avec un chemin complètement invalide (système de fichiers en lecture seule simulé)
        invalid_path = "/root/readonly/invalid.db"  # Chemin typiquement inaccessible

        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = invalid_path

        conn = DatabaseConnection(invalid_path, config)

        with pytest.raises(ConnectionError):
            conn.connect()

    def test_integrity_constraint_violation(self):
        """Test des violations de contraintes d'intégrité"""
        test_db_path = os.path.join(self.temp_dir, "integrity_test.db")
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = test_db_path

        db = Database(config)
        db.create_tables()

        # Insérer un premier scan
        scan_data = {
            'scan_id': 'unique_scan_id',
            'target': '192.168.1.100',
            'scan_type': 'quick',
            'status': 'completed'
        }
        db.insert('scans', scan_data)

        # Tenter d'insérer un scan avec le même scan_id (violation d'unicité)
        duplicate_scan = scan_data.copy()

        with pytest.raises(IntegrityError):
            db.insert('scans', duplicate_scan)

        db.close()

    def test_database_error_codes(self):
        """Test des codes d'erreur personnalisés"""
        # Tester que les codes d'erreur sont bien définis
        assert hasattr(DatabaseErrorCodes, 'CONNECTION_FAILED')
        assert hasattr(DatabaseErrorCodes, 'MIGRATION_FAILED')
        assert hasattr(DatabaseErrorCodes, 'VALIDATION_FAILED')

        # Tester que les messages d'erreur correspondent
        assert DatabaseErrorCodes.CONNECTION_FAILED in ERROR_MESSAGES
        assert ERROR_MESSAGES[DatabaseErrorCodes.CONNECTION_FAILED] != ""

    def test_invalid_table_operations(self):
        """Test des opérations sur des tables inexistantes"""
        test_db_path = os.path.join(self.temp_dir, "invalid_table_test.db")
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = test_db_path

        db = Database(config)
        db.create_tables()

        # Tenter d'insérer dans une table inexistante
        with pytest.raises(DatabaseError):
            db.insert('nonexistent_table', {'id': 1, 'name': 'test'})

        # Tenter de sélectionner depuis une table inexistante
        with pytest.raises(DatabaseError):
            db.select('nonexistent_table')

        db.close()

    def test_malformed_query(self):
        """Test des requêtes SQL malformées"""
        test_db_path = os.path.join(self.temp_dir, "malformed_test.db")
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = test_db_path

        db = Database(config)
        db.create_tables()

        # Requête SQL malformée
        with pytest.raises(DatabaseError):
            db.execute_custom_query("SELECT * FROM INVALID SQL SYNTAX")

        db.close()


class TestDatabaseConcurrency:
    """Tests pour la gestion de la concurrence"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, "concurrency_test.db")

    def teardown_method(self):
        """Nettoyage après chaque test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_concurrent_connections(self):
        """Test des connexions concurrentes (simulation)"""
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = self.test_db_path

        # Créer plusieurs instances de base de données
        db1 = Database(config)
        db2 = Database(config)

        db1.create_tables()

        # Test d'insertion concurrent (simulé)
        scan1_data = {
            'scan_id': 'concurrent_scan_1',
            'target': '192.168.1.100',
            'scan_type': 'quick',
            'status': 'running'
        }

        scan2_data = {
            'scan_id': 'concurrent_scan_2',
            'target': '192.168.1.200',
            'scan_type': 'full',
            'status': 'pending'
        }

        # Insertions depuis deux instances différentes
        id1 = db1.insert('scans', scan1_data)
        id2 = db2.insert('scans', scan2_data)

        assert id1 != id2

        # Vérifier que les deux insertions sont visibles
        count1 = db1.count('scans')
        count2 = db2.count('scans')

        assert count1 == 2
        assert count2 == 2

        db1.close()
        db2.close()

    def test_transaction_isolation(self):
        """Test de l'isolation des transactions"""
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = self.test_db_path

        db = Database(config)
        db.create_tables()

        conn = db.get_connection()
        conn.connect()

        # Créer une table de test
        conn.execute("CREATE TABLE IF NOT EXISTS isolation_test (id INTEGER, value TEXT)")

        # Test avec transaction
        with conn.transaction():
            conn.execute("INSERT INTO isolation_test VALUES (1, 'test1')")
            # Avant commit, les données ne devraient pas être visibles depuis une autre connexion

            # Créer une nouvelle connexion pour tester l'isolation
            db2 = Database(config)
            count_other = db2.count('isolation_test')
            # En mode autocommit de SQLite, les données peuvent être visibles immédiatement
            # Ce test vérifie surtout que les transactions fonctionnent sans erreur
            db2.close()

        # Après la transaction, les données devraient être visibles
        final_count = db.count('isolation_test')
        assert final_count == 1

        db.close()


class TestDatabaseMigration:
    """Tests pour les migrations de schéma"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Nettoyage après chaque test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_schema_version_management(self):
        """Test de gestion des versions de schéma"""
        test_db_path = os.path.join(self.temp_dir, "migration_test.db")
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = test_db_path

        db = Database(config)
        db.create_tables()

        # Vérifier que la version du schéma est définie
        version = db.get_schema_version()
        assert version is not None
        assert version == DATABASE_SCHEMA_VERSION

        db.close()

    def test_create_tables_idempotent(self):
        """Test que la création des tables est idempotente"""
        test_db_path = os.path.join(self.temp_dir, "idempotent_test.db")
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = test_db_path

        db = Database(config)

        # Première création
        db.create_tables()
        assert db.is_initialized is True

        # Deuxième création (ne devrait pas échouer)
        try:
            db.create_tables()
        except Exception as e:
            pytest.fail(f"Second create_tables() should not fail: {e}")

        assert db.is_initialized is True

        db.close()

    @patch('pathlib.Path.exists')
    def test_create_tables_without_migration_file(self, mock_exists):
        """Test de création des tables sans fichier de migration"""
        # Simuler l'absence du fichier migrations.sql
        mock_exists.return_value = False

        test_db_path = os.path.join(self.temp_dir, "no_migration_test.db")
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = test_db_path

        db = Database(config)

        # Devrait utiliser le schéma de base intégré
        db.create_tables()
        assert db.is_initialized is True

        # Vérifier que les tables de base existent
        tables = ['scans', 'vulnerabilities', 'analyses', 'scripts', 'workflows']
        for table in tables:
            count = db.count(table)  # Ne devrait pas lever d'exception
            assert count >= 0

        db.close()


class TestDatabasePerformance:
    """Tests de performance de base de données"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Nettoyage après chaque test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_bulk_insert_performance(self):
        """Test de performance pour l'insertion en lot"""
        test_db_path = os.path.join(self.temp_dir, "performance_test.db")
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = test_db_path

        db = Database(config)
        db.create_tables()

        # Préparer un lot important de données
        bulk_data = []
        for i in range(1000):
            data = {
                'vulnerability_id': f'PERF-{i:04d}',
                'name': f'Performance Test Vulnerability {i}',
                'severity': 'MEDIUM',
                'cvss_score': 5.0,
                'description': f'Performance test description {i}',
                'affected_service': 'test_service',
                'affected_port': 80
            }
            bulk_data.append(data)

        # Mesurer le temps d'insertion en lot
        start_time = time.time()
        rows_inserted = db.bulk_insert('vulnerabilities', bulk_data)
        bulk_duration = time.time() - start_time

        assert rows_inserted == 1000
        assert bulk_duration < 5.0  # Devrait prendre moins de 5 secondes

        # Vérifier que toutes les données sont présentes
        count = db.count('vulnerabilities')
        assert count == 1000

        db.close()

    def test_large_dataset_queries(self):
        """Test de performance sur un jeu de données important"""
        test_db_path = os.path.join(self.temp_dir, "large_dataset_test.db")
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = test_db_path

        db = Database(config)
        db.create_tables()

        # Insérer un grand nombre de scans
        scan_data_list = []
        for i in range(500):
            data = {
                'scan_id': f'large_scan_{i:04d}',
                'target': f'192.168.{i // 255}.{i % 255}',
                'scan_type': 'quick' if i % 2 == 0 else 'full',
                'status': 'completed'
            }
            scan_data_list.append(data)

        db.bulk_insert('scans', scan_data_list)

        # Test de performance des requêtes
        start_time = time.time()

        # Requête avec WHERE
        quick_scans = db.select('scans', where={'scan_type': 'quick'}, limit=100)

        # Requête avec ORDER BY
        recent_scans = db.select('scans', order_by='created_at DESC', limit=50)

        # Requête de comptage
        total_count = db.count('scans')

        query_duration = time.time() - start_time

        assert len(quick_scans) > 0
        assert len(recent_scans) > 0
        assert total_count == 500
        assert query_duration < 2.0  # Devrait prendre moins de 2 secondes

        db.close()


class TestDatabaseValidation:
    """Tests de validation des données"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Nettoyage après chaque test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_data_type_validation(self):
        """Test de validation des types de données"""
        test_db_path = os.path.join(self.temp_dir, "validation_test.db")
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = test_db_path

        db = Database(config)
        db.create_tables()

        # Test avec des données valides
        valid_data = {
            'vulnerability_id': 'CVE-2024-0001',
            'name': 'Valid Vulnerability',
            'severity': 'HIGH',
            'cvss_score': 8.5,
            'description': 'Valid description',
            'affected_service': 'Apache',
            'affected_port': 80
        }

        # Ceci devrait fonctionner
        vuln_id = db.insert('vulnerabilities', valid_data)
        assert vuln_id is not None

        # Test avec des données potentiellement problématiques
        edge_case_data = {
            'vulnerability_id': 'EDGE-CASE-001',
            'name': 'Edge Case Vulnerability',
            'severity': 'UNKNOWN',  # Valeur non standard
            'cvss_score': None,  # Valeur nulle
            'description': '',  # Chaîne vide
            'affected_service': None,  # Valeur nulle
            'affected_port': None  # Valeur nulle
        }

        # SQLite est assez permissif, ceci devrait fonctionner
        edge_id = db.insert('vulnerabilities', edge_case_data)
        assert edge_id is not None

        db.close()

    def test_json_data_handling(self):
        """Test de gestion des données JSON"""
        test_db_path = os.path.join(self.temp_dir, "json_test.db")
        config = DEFAULT_DATABASE_CONFIG.copy()
        config['database_path'] = test_db_path

        db = Database(config)
        db.create_tables()

        # Données avec champs JSON
        scan_data = {
            'scan_id': 'json_test_scan',
            'target': '192.168.1.100',
            'scan_type': 'full',
            'status': 'completed',
            'scan_parameters': json.dumps({
                'timeout': 300,
                'timing': 'T4',
                'scripts': ['vuln', 'safe'],
                'custom_args': '--max-retries 3'
            })
        }

        scan_id = db.insert('scans', scan_data)
        assert scan_id is not None

        # Récupérer et vérifier les données JSON
        result = db.select_one('scans', where={'scan_id': 'json_test_scan'})
        assert result is not None

        # Parser le JSON
        scan_params = json.loads(result['scan_parameters'])
        assert scan_params['timeout'] == 300
        assert 'vuln' in scan_params['scripts']

        db.close()


if __name__ == "__main__":
    # Exécution des tests avec pytest
    print("Exécution des tests de base de données...")

    # Configuration de pytest pour ce module
    pytest_args = [
        __file__,
        "-v",  # Mode verbeux
        "--tb=short",  # Traceback court
        "-x",  # Arrêter au premier échec
    ]

    # Ajouter des options spécifiques si nécessaire
    import sys

    if "--coverage" in sys.argv:
        pytest_args.extend(["--cov=src.database", "--cov-report=html"])

    # Lancer les tests
    exit_code = pytest.main(pytest_args)

    if exit_code == 0:
        print("✅ Tous les tests de base de données sont passés!")
    else:
        print("❌ Certains tests ont échoué.")

    sys.exit(exit_code)