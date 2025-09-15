"""
Module Database pour l'Agent IA de Cybersécurité

Ce module implémente le gestionnaire principal de base de données utilisant SQLite.
Il fournit une interface unifiée pour toutes les opérations CRUD et la gestion
du cycle de vie de la base de données.

Fonctionnalités :
- Connexion et configuration SQLite optimisée
- Création et migration des schémas
- Opérations CRUD pour tous les modèles
- Gestion des transactions
- Pool de connexions
- Backup et restauration automatiques
- Monitoring et statistiques
"""

import asyncio
import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple, Iterator
import uuid

from src.utils.logger import setup_logger
from . import (
    DatabaseError, ConnectionError, MigrationError, ValidationError,
    IntegrityError, DatabaseErrorCodes, ERROR_MESSAGES,
    DEFAULT_DATABASE_CONFIG, DATABASE_SCHEMA_VERSION
)

# Configuration du logging
logger = setup_logger(__name__)


# === CLASSE DE CONNEXION ===

class DatabaseConnection:
    """
    Gestionnaire de connexion SQLite avec optimisations

    Encapsule une connexion SQLite avec configuration optimisée
    pour les performances et la sécurité.
    """

    def __init__(self, database_path: str, config: Dict[str, Any]):
        """
        Initialise une connexion à la base de données

        Args:
            database_path: Chemin vers le fichier SQLite
            config: Configuration de la connexion
        """
        self.database_path = database_path
        self.config = config
        self.connection: Optional[sqlite3.Connection] = None
        self.is_connected = False
        self.lock = threading.RLock()

    def connect(self) -> sqlite3.Connection:
        """
        Établit la connexion à la base de données

        Returns:
            sqlite3.Connection: Connexion active

        Raises:
            ConnectionError: Si la connexion échoue
        """
        with self.lock:
            if self.is_connected and self.connection:
                return self.connection

            try:
                # Créer le répertoire si nécessaire
                db_path = Path(self.database_path)
                db_path.parent.mkdir(parents=True, exist_ok=True)

                # Établir la connexion avec timeout
                self.connection = sqlite3.connect(
                    self.database_path,
                    timeout=self.config.get('connection_timeout', 30),
                    isolation_level=None  # Autocommit mode
                )

                # Configuration de la connexion
                self._configure_connection()

                self.is_connected = True
                logger.debug(f"Connexion établie: {self.database_path}")

                return self.connection

            except sqlite3.Error as e:
                logger.error(f"Erreur connexion SQLite: {e}")
                raise ConnectionError(
                    f"Impossible de se connecter à la base: {str(e)}",
                    DatabaseErrorCodes.CONNECTION_FAILED
                )
            except Exception as e:
                logger.error(f"Erreur inattendue lors de la connexion: {e}")
                raise ConnectionError(
                    f"Erreur de connexion: {str(e)}",
                    DatabaseErrorCodes.CONNECTION_FAILED
                )

    def _configure_connection(self):
        """Configure la connexion SQLite avec les optimisations"""
        if not self.connection:
            return

        cursor = self.connection.cursor()

        try:
            # Configuration des PRAGMAs pour les performances
            pragmas = [
                f"PRAGMA journal_mode = {self.config.get('journal_mode', 'WAL')}",
                f"PRAGMA synchronous = {self.config.get('synchronous', 'NORMAL')}",
                f"PRAGMA cache_size = {self.config.get('cache_size', 10000)}",
                f"PRAGMA temp_store = {self.config.get('temp_store', 'MEMORY')}",
                f"PRAGMA busy_timeout = {self.config.get('busy_timeout', 30000)}",
            ]

            # Activer les clés étrangères si configuré
            if self.config.get('foreign_keys', True):
                pragmas.append("PRAGMA foreign_keys = ON")

            # Auto vacuum si configuré
            if self.config.get('auto_vacuum', True):
                pragmas.append("PRAGMA auto_vacuum = INCREMENTAL")

            # Exécuter les PRAGMAs
            for pragma in pragmas:
                cursor.execute(pragma)
                logger.debug(f"PRAGMA appliqué: {pragma}")

            # Configurer le row factory pour des résultats dictionnaire
            self.connection.row_factory = sqlite3.Row

        except sqlite3.Error as e:
            logger.warning(f"Erreur configuration PRAGMA: {e}")
        finally:
            cursor.close()

    def close(self):
        """Ferme la connexion à la base de données"""
        with self.lock:
            if self.connection:
                try:
                    self.connection.close()
                    logger.debug("Connexion fermée")
                except sqlite3.Error as e:
                    logger.warning(f"Erreur fermeture connexion: {e}")
                finally:
                    self.connection = None
                    self.is_connected = False

    def execute(self, query: str, params: Tuple = ()) -> sqlite3.Cursor:
        """
        Exécute une requête SQL

        Args:
            query: Requête SQL
            params: Paramètres de la requête

        Returns:
            sqlite3.Cursor: Curseur avec les résultats
        """
        if not self.is_connected:
            self.connect()

        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            return cursor
        except sqlite3.Error as e:
            logger.error(f"Erreur exécution requête: {e}")
            logger.error(f"Requête: {query}")
            logger.error(f"Paramètres: {params}")
            raise DatabaseError(
                f"Erreur d'exécution SQL: {str(e)}",
                DatabaseErrorCodes.SELECT_FAILED
            )

    def executemany(self, query: str, params_list: List[Tuple]) -> sqlite3.Cursor:
        """
        Exécute une requête avec plusieurs jeux de paramètres

        Args:
            query: Requête SQL
            params_list: Liste des paramètres

        Returns:
            sqlite3.Cursor: Curseur avec les résultats
        """
        if not self.is_connected:
            self.connect()

        try:
            cursor = self.connection.cursor()
            cursor.executemany(query, params_list)
            return cursor
        except sqlite3.Error as e:
            logger.error(f"Erreur exécution multiple: {e}")
            raise DatabaseError(
                f"Erreur d'exécution multiple: {str(e)}",
                DatabaseErrorCodes.INSERT_FAILED
            )

    @contextmanager
    def transaction(self):
        """
        Gestionnaire de contexte pour les transactions

        Usage:
            with db_conn.transaction():
                db_conn.execute("INSERT ...")
                db_conn.execute("UPDATE ...")
        """
        if not self.is_connected:
            self.connect()

        try:
            self.connection.execute("BEGIN")
            yield
            self.connection.execute("COMMIT")
        except Exception as e:
            self.connection.execute("ROLLBACK")
            logger.error(f"Transaction annulée: {e}")
            raise


# === CLASSE PRINCIPALE ===

class Database:
    """
    Gestionnaire principal de base de données

    Fournit une interface unifiée pour toutes les opérations
    de base de données de l'agent IA de cybersécurité.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialise le gestionnaire de base de données

        Args:
            config: Configuration de la base de données
        """
        self.config = config or DEFAULT_DATABASE_CONFIG.copy()
        self.database_path = self.config['database_path']

        # Pool de connexions (simple implémentation)
        self._connections: Dict[int, DatabaseConnection] = {}
        self._connection_lock = threading.RLock()

        # Statistiques
        self.stats = {
            "total_queries": 0,
            "total_inserts": 0,
            "total_updates": 0,
            "total_deletes": 0,
            "total_selects": 0,
            "connection_count": 0,
            "last_backup": None,
            "created_at": datetime.utcnow()
        }

        # État de la base
        self.is_initialized = False
        self.schema_version = None

        logger.info(f"Database manager initialisé: {self.database_path}")

    def get_connection(self) -> DatabaseConnection:
        """
        Récupère une connexion du pool (ou en crée une nouvelle)

        Returns:
            DatabaseConnection: Connexion active
        """
        thread_id = threading.get_ident()

        with self._connection_lock:
            if thread_id not in self._connections:
                self._connections[thread_id] = DatabaseConnection(
                    self.database_path, self.config
                )
                self.stats["connection_count"] += 1

            return self._connections[thread_id]

    def create_tables(self):
        """
        Crée toutes les tables de la base de données

        Raises:
            MigrationError: Si la création échoue
        """
        try:
            conn = self.get_connection()
            conn.connect()

            # Lire le script de migration
            migrations_file = Path(__file__).parent / "migrations.sql"

            if migrations_file.exists():
                with open(migrations_file, 'r', encoding='utf-8') as f:
                    migration_script = f.read()

                # Exécuter le script de migration
                cursor = conn.connection.cursor()
                cursor.executescript(migration_script)
                cursor.close()

                logger.info("Tables créées avec succès")
            else:
                # Créer les tables avec le schéma minimal
                self._create_basic_schema(conn)

            # Définir la version du schéma
            self._set_schema_version(DATABASE_SCHEMA_VERSION)
            self.is_initialized = True

        except Exception as e:
            logger.error(f"Erreur création des tables: {e}")
            raise MigrationError(
                f"Impossible de créer les tables: {str(e)}",
                DatabaseErrorCodes.MIGRATION_FAILED
            )

    def _create_basic_schema(self, conn: DatabaseConnection):
        """Crée le schéma de base si pas de fichier de migration"""

        basic_schema = """
        -- Table des scans
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            duration REAL,
            nmap_version TEXT,
            scan_parameters TEXT, -- JSON
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des vulnérabilités
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL,
            description TEXT,
            affected_service TEXT,
            affected_port INTEGER,
            cve_ids TEXT, -- JSON array
            references TEXT, -- JSON array
            detection_method TEXT,
            confidence TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des analyses IA
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT UNIQUE NOT NULL,
            target_system TEXT NOT NULL,
            ai_model_used TEXT,
            confidence_score REAL,
            processing_time REAL,
            analysis_summary TEXT, -- JSON
            remediation_plan TEXT, -- JSON
            analyzed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des scripts
        CREATE TABLE IF NOT EXISTS scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_id TEXT UNIQUE NOT NULL,
            vulnerability_id TEXT NOT NULL,
            target_system TEXT NOT NULL,
            script_type TEXT NOT NULL,
            script_content TEXT NOT NULL,
            rollback_script TEXT,
            risk_level TEXT,
            validation_status TEXT,
            estimated_duration TEXT,
            requires_reboot BOOLEAN DEFAULT FALSE,
            requires_sudo BOOLEAN DEFAULT TRUE,
            generated_at TIMESTAMP,
            generated_by TEXT,
            script_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id)
        );

        -- Table des workflows
        CREATE TABLE IF NOT EXISTS workflows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow_id TEXT UNIQUE NOT NULL,
            workflow_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            priority TEXT DEFAULT 'normal',
            created_by TEXT,
            parameters TEXT, -- JSON
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            duration REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table de liaison scan-vulnérabilités
        CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            vulnerability_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id),
            UNIQUE(scan_id, vulnerability_id)
        );

        -- Index pour les performances
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_scripts_vulnerability ON scripts(vulnerability_id);
        CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status);

        -- Table de métadonnées
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """

        cursor = conn.connection.cursor()
        cursor.executescript(basic_schema)
        cursor.close()

        logger.info("Schéma de base créé")

    def _set_schema_version(self, version: str):
        """Définit la version du schéma dans la base"""
        try:
            conn = self.get_connection()
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ("schema_version", version)
            )
            self.schema_version = version
            logger.info(f"Version du schéma définie: {version}")
        except Exception as e:
            logger.warning(f"Erreur définition version schéma: {e}")

    def get_schema_version(self) -> Optional[str]:
        """
        Récupère la version du schéma

        Returns:
            str: Version du schéma ou None
        """
        try:
            conn = self.get_connection()
            cursor = conn.execute(
                "SELECT value FROM metadata WHERE key = ?",
                ("schema_version",)
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception:
            return None

    # === OPÉRATIONS CRUD GÉNÉRIQUES ===

    def insert(self, table: str, data: Dict[str, Any]) -> str:
        """
        Insère un enregistrement dans une table

        Args:
            table: Nom de la table
            data: Données à insérer

        Returns:
            str: ID de l'enregistrement inséré

        Raises:
            DatabaseError: Si l'insertion échoue
        """
        try:
            # Ajouter les timestamps automatiques
            if 'created_at' not in data:
                data['created_at'] = datetime.utcnow().isoformat()

            if 'updated_at' not in data and 'created_at' in data:
                data['updated_at'] = data['created_at']

            # Construire la requête
            columns = list(data.keys())
            placeholders = ['?' for _ in columns]
            values = [data[col] for col in columns]

            query = f"""
                INSERT INTO {table} ({', '.join(columns)})
                VALUES ({', '.join(placeholders)})
            """

            conn = self.get_connection()
            cursor = conn.execute(query, tuple(values))

            # Récupérer l'ID inséré
            row_id = cursor.lastrowid
            cursor.close()

            self.stats["total_queries"] += 1
            self.stats["total_inserts"] += 1

            logger.debug(f"Insertion dans {table}: ID {row_id}")
            return str(row_id)

        except sqlite3.IntegrityError as e:
            logger.error(f"Erreur intégrité insertion {table}: {e}")
            raise IntegrityError(
                f"Violation de contrainte: {str(e)}",
                DatabaseErrorCodes.CONSTRAINT_VIOLATION
            )
        except Exception as e:
            logger.error(f"Erreur insertion {table}: {e}")
            raise DatabaseError(
                f"Erreur d'insertion: {str(e)}",
                DatabaseErrorCodes.INSERT_FAILED
            )

    def update(self, table: str, data: Dict[str, Any], where: Dict[str, Any]) -> int:
        """
        Met à jour des enregistrements dans une table

        Args:
            table: Nom de la table
            data: Données à mettre à jour
            where: Conditions WHERE

        Returns:
            int: Nombre d'enregistrements mis à jour
        """
        try:
            # Ajouter le timestamp de mise à jour
            data['updated_at'] = datetime.utcnow().isoformat()

            # Construire la requête
            set_clauses = [f"{col} = ?" for col in data.keys()]
            where_clauses = [f"{col} = ?" for col in where.keys()]

            query = f"""
                UPDATE {table}
                SET {', '.join(set_clauses)}
                WHERE {' AND '.join(where_clauses)}
            """

            params = list(data.values()) + list(where.values())

            conn = self.get_connection()
            cursor = conn.execute(query, tuple(params))

            rows_affected = cursor.rowcount
            cursor.close()

            self.stats["total_queries"] += 1
            self.stats["total_updates"] += 1

            logger.debug(f"Mise à jour {table}: {rows_affected} lignes")
            return rows_affected

        except Exception as e:
            logger.error(f"Erreur mise à jour {table}: {e}")
            raise DatabaseError(
                f"Erreur de mise à jour: {str(e)}",
                DatabaseErrorCodes.UPDATE_FAILED
            )

    def delete(self, table: str, where: Dict[str, Any]) -> int:
        """
        Supprime des enregistrements d'une table

        Args:
            table: Nom de la table
            where: Conditions WHERE

        Returns:
            int: Nombre d'enregistrements supprimés
        """
        try:
            where_clauses = [f"{col} = ?" for col in where.keys()]

            query = f"""
                DELETE FROM {table}
                WHERE {' AND '.join(where_clauses)}
            """

            params = list(where.values())

            conn = self.get_connection()
            cursor = conn.execute(query, tuple(params))

            rows_affected = cursor.rowcount
            cursor.close()

            self.stats["total_queries"] += 1
            self.stats["total_deletes"] += 1

            logger.debug(f"Suppression {table}: {rows_affected} lignes")
            return rows_affected

        except Exception as e:
            logger.error(f"Erreur suppression {table}: {e}")
            raise DatabaseError(
                f"Erreur de suppression: {str(e)}",
                DatabaseErrorCodes.DELETE_FAILED
            )

    def select(
            self,
            table: str,
            columns: List[str] = None,
            where: Dict[str, Any] = None,
            order_by: str = None,
            limit: int = None,
            offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Sélectionne des enregistrements d'une table

        Args:
            table: Nom de la table
            columns: Colonnes à sélectionner (None = toutes)
            where: Conditions WHERE
            order_by: Clause ORDER BY
            limit: Limite du nombre de résultats
            offset: Décalage pour la pagination

        Returns:
            List[Dict]: Liste des enregistrements
        """
        try:
            # Construire la requête
            cols = ', '.join(columns) if columns else '*'
            query = f"SELECT {cols} FROM {table}"
            params = []

            # Ajouter WHERE
            if where:
                where_clauses = [f"{col} = ?" for col in where.keys()]
                query += f" WHERE {' AND '.join(where_clauses)}"
                params.extend(where.values())

            # Ajouter ORDER BY
            if order_by:
                query += f" ORDER BY {order_by}"

            # Ajouter LIMIT et OFFSET
            if limit:
                query += f" LIMIT {limit}"
                if offset:
                    query += f" OFFSET {offset}"

            conn = self.get_connection()
            cursor = conn.execute(query, tuple(params))

            # Convertir les résultats en dictionnaires
            results = []
            for row in cursor.fetchall():
                results.append(dict(row))

            cursor.close()

            self.stats["total_queries"] += 1
            self.stats["total_selects"] += 1

            logger.debug(f"Sélection {table}: {len(results)} résultats")
            return results

        except Exception as e:
            logger.error(f"Erreur sélection {table}: {e}")
            raise DatabaseError(
                f"Erreur de sélection: {str(e)}",
                DatabaseErrorCodes.SELECT_FAILED
            )

    def select_one(
            self,
            table: str,
            columns: List[str] = None,
            where: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Sélectionne un seul enregistrement

        Args:
            table: Nom de la table
            columns: Colonnes à sélectionner
            where: Conditions WHERE

        Returns:
            Dict ou None: Enregistrement trouvé ou None
        """
        results = self.select(table, columns, where, limit=1)
        return results[0] if results else None

    def count(self, table: str, where: Dict[str, Any] = None) -> int:
        """
        Compte les enregistrements d'une table

        Args:
            table: Nom de la table
            where: Conditions WHERE

        Returns:
            int: Nombre d'enregistrements
        """
        try:
            query = f"SELECT COUNT(*) as count FROM {table}"
            params = []

            if where:
                where_clauses = [f"{col} = ?" for col in where.keys()]
                query += f" WHERE {' AND '.join(where_clauses)}"
                params.extend(where.values())

            conn = self.get_connection()
            cursor = conn.execute(query, tuple(params))

            result = cursor.fetchone()
            count = result['count'] if result else 0

            cursor.close()
            self.stats["total_queries"] += 1

            return count

        except Exception as e:
            logger.error(f"Erreur comptage {table}: {e}")
            raise DatabaseError(
                f"Erreur de comptage: {str(e)}",
                DatabaseErrorCodes.SELECT_FAILED
            )

    # === OPÉRATIONS SPÉCIALISÉES ===

    def save_scan_result(self, scan_result) -> str:
        """
        Sauvegarde un résultat de scan complet

        Args:
            scan_result: Objet ScanResult à sauvegarder

        Returns:
            str: ID de l'enregistrement
        """
        try:
            with self.get_connection().transaction():
                # Insérer le scan
                scan_data = {
                    'scan_id': scan_result.scan_id,
                    'target': scan_result.target,
                    'scan_type': scan_result.scan_type,
                    'status': 'completed',
                    'started_at': scan_result.started_at.isoformat(),
                    'completed_at': scan_result.completed_at.isoformat(),
                    'duration': scan_result.duration,
                    'nmap_version': scan_result.nmap_version,
                    'scan_parameters': json.dumps(scan_result.scan_parameters)
                }

                scan_id = self.insert('scans', scan_data)

                # Insérer les vulnérabilités
                for vuln in scan_result.vulnerabilities:
                    vuln_data = {
                        'vulnerability_id': vuln.vulnerability_id,
                        'name': vuln.name,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score,
                        'description': vuln.description,
                        'affected_service': vuln.affected_service,
                        'affected_port': vuln.affected_port,
                        'cve_ids': json.dumps(vuln.cve_ids),
                        'references': json.dumps(vuln.references),
                        'detection_method': vuln.detection_method,
                        'confidence': vuln.confidence
                    }

                    # Insérer ou mettre à jour la vulnérabilité
                    existing = self.select_one('vulnerabilities',
                                               where={'vulnerability_id': vuln.vulnerability_id})

                    if not existing:
                        self.insert('vulnerabilities', vuln_data)

                    # Créer la liaison scan-vulnérabilité
                    link_data = {
                        'scan_id': scan_result.scan_id,
                        'vulnerability_id': vuln.vulnerability_id
                    }

                    try:
                        self.insert('scan_vulnerabilities', link_data)
                    except IntegrityError:
                        # Liaison déjà existante
                        pass

                logger.info(f"Scan sauvegardé: {scan_result.scan_id}")
                return scan_id

        except Exception as e:
            logger.error(f"Erreur sauvegarde scan: {e}")
            raise DatabaseError(f"Impossible de sauvegarder le scan: {str(e)}")

    def get_scan_history(
            self,
            target: str = None,
            limit: int = 50,
            offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Récupère l'historique des scans

        Args:
            target: Filtrer par cible (optionnel)
            limit: Nombre maximum de résultats
            offset: Décalage pour pagination

        Returns:
            List[Dict]: Historique des scans
        """
        where = {'target': target} if target else None

        return self.select(
            'scans',
            where=where,
            order_by='created_at DESC',
            limit=limit,
            offset=offset
        )

    def get_vulnerabilities_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Récupère les vulnérabilités par niveau de gravité

        Args:
            severity: Niveau de gravité (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            List[Dict]: Vulnérabilités correspondantes
        """
        return self.select(
            'vulnerabilities',
            where={'severity': severity},
            order_by='cvss_score DESC'
        )

    def cleanup_old_data(self, retention_days: int = 30) -> Dict[str, int]:
        """
        Nettoie les anciennes données

        Args:
            retention_days: Nombre de jours de rétention

        Returns:
            Dict: Nombre d'enregistrements supprimés par table
        """
        cutoff_date = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()

        cleanup_stats = {}

        try:
            with self.get_connection().transaction():
                # Nettoyer les scans anciens
                conn = self.get_connection()
                cursor = conn.execute(
                    "DELETE FROM scans WHERE created_at < ?",
                    (cutoff_date,)
                )
                cleanup_stats['scans'] = cursor.rowcount

                # Nettoyer les workflows anciens
                cursor = conn.execute(
                    "DELETE FROM workflows WHERE created_at < ?",
                    (cutoff_date,)
                )
                cleanup_stats['workflows'] = cursor.rowcount

                # Les vulnérabilités sont conservées (référence)
                # Les analyses et scripts peuvent être nettoyés
                cursor = conn.execute(
                    "DELETE FROM analyses WHERE created_at < ?",
                    (cutoff_date,)
                )
                cleanup_stats['analyses'] = cursor.rowcount

                cursor.close()

            total_cleaned = sum(cleanup_stats.values())
            total_cleaned = sum(cleanup_stats.values())
            logger.info(f"Nettoyage terminé: {total_cleaned} enregistrements supprimés")

            return cleanup_stats

        except Exception as e:
            logger.error(f"Erreur nettoyage données: {e}")
            raise DatabaseError(f"Erreur lors du nettoyage: {str(e)}")

            # === OPÉRATIONS DE MAINTENANCE ===

        def vacuum(self):
            """
            Optimise la base de données (VACUUM)

            Récupère l'espace libre et optimise les performances
            """
            try:
                conn = self.get_connection()
                cursor = conn.execute("VACUUM")
                cursor.close()
                logger.info("VACUUM exécuté avec succès")
            except Exception as e:
                logger.error(f"Erreur VACUUM: {e}")
                raise DatabaseError(f"Erreur d'optimisation: {str(e)}")

        def analyze(self):
            """
            Met à jour les statistiques de la base (ANALYZE)

            Améliore les performances des requêtes
            """
            try:
                conn = self.get_connection()
                cursor = conn.execute("ANALYZE")
                cursor.close()
                logger.info("ANALYZE exécuté avec succès")
            except Exception as e:
                logger.error(f"Erreur ANALYZE: {e}")
                raise DatabaseError(f"Erreur d'analyse: {str(e)}")

        def reindex(self):
            """
            Reconstruit tous les index de la base

            Utile après de nombreuses modifications
            """
            try:
                conn = self.get_connection()
                cursor = conn.execute("REINDEX")
                cursor.close()
                logger.info("REINDEX exécuté avec succès")
            except Exception as e:
                logger.error(f"Erreur REINDEX: {e}")
                raise DatabaseError(f"Erreur de réindexation: {str(e)}")

        def optimize(self):
            """
            Optimisation complète de la base de données

            Exécute VACUUM, ANALYZE et REINDEX
            """
            logger.info("Début optimisation de la base de données")
            start_time = time.time()

            try:
                self.vacuum()
                self.analyze()
                self.reindex()

                duration = time.time() - start_time
                logger.info(f"Optimisation terminée en {duration:.2f}s")

            except Exception as e:
                logger.error(f"Erreur optimisation: {e}")
                raise

            # === BACKUP ET RESTAURATION ===

        def backup(self, backup_path: str = None, compress: bool = True) -> str:
            """
            Crée une sauvegarde de la base de données

            Args:
                backup_path: Chemin de sauvegarde (optionnel)
                compress: Compresser la sauvegarde

            Returns:
                str: Chemin du fichier de sauvegarde
            """
            from . import backup_database

            try:
                backup_file = backup_database(
                    self.database_path,
                    backup_path,
                    compress
                )

                self.stats["last_backup"] = datetime.utcnow().isoformat()
                logger.info(f"Sauvegarde créée: {backup_file}")

                return backup_file

            except Exception as e:
                logger.error(f"Erreur sauvegarde: {e}")
                raise DatabaseError(f"Erreur de sauvegarde: {str(e)}")

        def restore(self, backup_path: str, verify_integrity: bool = True) -> bool:
            """
            Restaure la base depuis une sauvegarde

            Args:
                backup_path: Chemin vers la sauvegarde
                verify_integrity: Vérifier l'intégrité

            Returns:
                bool: True si la restauration a réussi
            """
            from . import restore_database

            try:
                # Fermer toutes les connexions
                self.close_all_connections()

                # Restaurer
                success = restore_database(
                    backup_path,
                    self.database_path,
                    verify_integrity
                )

                if success:
                    # Réinitialiser les connexions
                    self._connections.clear()
                    self.is_initialized = False
                    logger.info("Base de données restaurée avec succès")

                return success

            except Exception as e:
                logger.error(f"Erreur restauration: {e}")
                raise DatabaseError(f"Erreur de restauration: {str(e)}")

        def auto_backup(self) -> bool:
            """
            Sauvegarde automatique selon la configuration

            Returns:
                bool: True si une sauvegarde a été créée
            """
            if not self.config.get('backup_enabled', True):
                return False

            try:
                # Vérifier si une sauvegarde est nécessaire
                last_backup = self.stats.get("last_backup")
                if last_backup:
                    last_backup_dt = datetime.fromisoformat(last_backup)
                    if (datetime.utcnow() - last_backup_dt).days < 1:
                        return False  # Sauvegarde récente

                # Créer la sauvegarde
                backup_file = self.backup()

                # Nettoyer les anciennes sauvegardes
                self._cleanup_old_backups()

                return True

            except Exception as e:
                logger.warning(f"Erreur sauvegarde automatique: {e}")
                return False

        def _cleanup_old_backups(self):
            """Nettoie les anciennes sauvegardes"""
            try:
                retention_days = self.config.get('backup_retention_days', 30)
                backup_dir = Path(self.database_path).parent / "backups"

                if not backup_dir.exists():
                    return

                cutoff_time = time.time() - (retention_days * 24 * 3600)

                for backup_file in backup_dir.glob("*.db*"):
                    if backup_file.stat().st_mtime < cutoff_time:
                        backup_file.unlink()
                        logger.debug(f"Ancienne sauvegarde supprimée: {backup_file}")

            except Exception as e:
                logger.warning(f"Erreur nettoyage sauvegardes: {e}")

            # === STATISTIQUES ET MONITORING ===

        def get_stats(self) -> Dict[str, Any]:
            """
            Retourne les statistiques de la base de données

            Returns:
                Dict: Statistiques complètes
            """
            try:
                # Statistiques des tables
                table_stats = {}
                tables = ['scans', 'vulnerabilities', 'analyses', 'scripts', 'workflows']

                for table in tables:
                    try:
                        count = self.count(table)
                        table_stats[table] = count
                    except:
                        table_stats[table] = 0

                # Informations sur le fichier
                db_path = Path(self.database_path)
                file_size = db_path.stat().st_size if db_path.exists() else 0

                # Statistiques de performance
                conn = self.get_connection()
                cursor = conn.execute("PRAGMA page_count")
                page_count = cursor.fetchone()[0] if cursor.fetchone() else 0

                cursor = conn.execute("PRAGMA page_size")
                page_size = cursor.fetchone()[0] if cursor.fetchone() else 0

                cursor.close()

                return {
                    **self.stats,
                    "database_path": self.database_path,
                    "file_size_bytes": file_size,
                    "file_size_mb": round(file_size / 1024 / 1024, 2),
                    "schema_version": self.get_schema_version(),
                    "table_counts": table_stats,
                    "page_count": page_count,
                    "page_size": page_size,
                    "estimated_pages_used": page_count,
                    "connection_pool_size": len(self._connections),
                    "is_initialized": self.is_initialized
                }

            except Exception as e:
                logger.error(f"Erreur récupération statistiques: {e}")
                return self.stats.copy()

        def health_check(self) -> Dict[str, Any]:
            """
            Vérifie la santé de la base de données

            Returns:
                Dict: Rapport de santé
            """
            health_report = {
                "healthy": True,
                "issues": [],
                "warnings": [],
                "performance_metrics": {}
            }

            try:
                # Test de connectivité
                conn = self.get_connection()
                conn.connect()

                # Vérification d'intégrité
                cursor = conn.execute("PRAGMA integrity_check")
                integrity_result = cursor.fetchone()

                if integrity_result and integrity_result[0] != "ok":
                    health_report["healthy"] = False
                    health_report["issues"].append(f"Intégrité compromise: {integrity_result[0]}")

                # Vérification des performances
                stats = self.get_stats()

                # Alertes de performance
                if stats["file_size_mb"] > 1000:  # 1GB
                    health_report["warnings"].append("Base de données volumineuse (>1GB)")

                if stats["total_queries"] > 0:
                    query_types = {
                        "selects": stats["total_selects"],
                        "inserts": stats["total_inserts"],
                        "updates": stats["total_updates"],
                        "deletes": stats["total_deletes"]
                    }
                    health_report["performance_metrics"] = query_types

                # Vérification de l'espace libre
                db_path = Path(self.database_path)
                if db_path.exists():
                    free_space = db_path.parent.stat().st_size  # Approximation
                    if free_space < 100 * 1024 * 1024:  # 100MB
                        health_report["warnings"].append("Espace disque faible")

                cursor.close()

            except Exception as e:
                health_report["healthy"] = False
                health_report["issues"].append(f"Erreur vérification santé: {str(e)}")

            return health_report

            # === GESTION DES CONNEXIONS ===

        def close_all_connections(self):
            """Ferme toutes les connexions du pool"""
            with self._connection_lock:
                for conn in self._connections.values():
                    try:
                        conn.close()
                    except:
                        pass

                self._connections.clear()
                logger.info("Toutes les connexions fermées")

        def close(self):
            """Ferme le gestionnaire de base de données"""
            logger.info("Fermeture du gestionnaire de base de données")

            # Sauvegarde automatique avant fermeture
            if self.config.get('backup_enabled', True):
                try:
                    self.auto_backup()
                except:
                    pass

            # Fermer toutes les connexions
            self.close_all_connections()

            logger.info("Gestionnaire de base de données fermé")

        def __enter__(self):
            """Support du gestionnaire de contexte"""
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            """Fermeture automatique avec gestionnaire de contexte"""
            self.close()

            # === MÉTHODES AVANCÉES ===

        def execute_custom_query(
                self,
                query: str,
                params: Tuple = (),
                fetch_results: bool = True
        ) -> Optional[List[Dict[str, Any]]]:
            """
            Exécute une requête SQL personnalisée

            Args:
                query: Requête SQL à exécuter
                params: Paramètres de la requête
                fetch_results: Récupérer les résultats

            Returns:
                List[Dict] ou None: Résultats de la requête
            """
            try:
                conn = self.get_connection()
                cursor = conn.execute(query, params)

                results = None
                if fetch_results:
                    results = []
                    for row in cursor.fetchall():
                        results.append(dict(row))

                cursor.close()
                self.stats["total_queries"] += 1

                return results

            except Exception as e:
                logger.error(f"Erreur requête personnalisée: {e}")
                raise DatabaseError(f"Erreur d'exécution: {str(e)}")

        def bulk_insert(self, table: str, data_list: List[Dict[str, Any]]) -> int:
            """
            Insertion en lot pour de meilleures performances

            Args:
                table: Nom de la table
                data_list: Liste des enregistrements à insérer

            Returns:
                int: Nombre d'enregistrements insérés
            """
            if not data_list:
                return 0

            try:
                # Ajouter les timestamps
                current_time = datetime.utcnow().isoformat()
                for data in data_list:
                    if 'created_at' not in data:
                        data['created_at'] = current_time
                    if 'updated_at' not in data:
                        data['updated_at'] = current_time

                # Préparer la requête
                columns = list(data_list[0].keys())
                placeholders = ['?' for _ in columns]

                query = f"""
                            INSERT INTO {table} ({', '.join(columns)})
                            VALUES ({', '.join(placeholders)})
                        """

                # Préparer les paramètres
                params_list = []
                for data in data_list:
                    params = [data[col] for col in columns]
                    params_list.append(tuple(params))

                # Exécution en lot
                conn = self.get_connection()

                with conn.transaction():
                    cursor = conn.executemany(query, params_list)
                    rows_inserted = cursor.rowcount
                    cursor.close()

                self.stats["total_queries"] += 1
                self.stats["total_inserts"] += rows_inserted

                logger.info(f"Insertion en lot {table}: {rows_inserted} enregistrements")
                return rows_inserted

            except Exception as e:
                logger.error(f"Erreur insertion en lot {table}: {e}")
                raise DatabaseError(f"Erreur d'insertion en lot: {str(e)}")

        def get_table_info(self, table: str) -> Dict[str, Any]:
            """
            Récupère les informations sur une table

            Args:
                table: Nom de la table

            Returns:
                Dict: Informations sur la table
            """
            try:
                conn = self.get_connection()

                # Informations sur les colonnes
                cursor = conn.execute(f"PRAGMA table_info({table})")
                columns = []
                for row in cursor.fetchall():
                    columns.append({
                        "name": row[1],
                        "type": row[2],
                        "not_null": bool(row[3]),
                        "default_value": row[4],
                        "primary_key": bool(row[5])
                    })

                # Index de la table
                cursor = conn.execute(f"PRAGMA index_list({table})")
                indexes = []
                for row in cursor.fetchall():
                    indexes.append({
                        "name": row[1],
                        "unique": bool(row[2]),
                        "origin": row[3]
                    })

                # Clés étrangères
                cursor = conn.execute(f"PRAGMA foreign_key_list({table})")
                foreign_keys = []
                for row in cursor.fetchall():
                    foreign_keys.append({
                        "column": row[3],
                        "referenced_table": row[2],
                        "referenced_column": row[4]
                    })

                cursor.close()

                # Compter les enregistrements
                record_count = self.count(table)

                return {
                    "table_name": table,
                    "columns": columns,
                    "indexes": indexes,
                    "foreign_keys": foreign_keys,
                    "record_count": record_count
                }

            except Exception as e:
                logger.error(f"Erreur info table {table}: {e}")
                return {"error": str(e)}

        # === FONCTIONS UTILITAIRES ===

        def create_database_manager(config: Dict[str, Any] = None) -> Database:
            """
            Factory pour créer un gestionnaire de base de données

            Args:
                config: Configuration personnalisée

            Returns:
                Database: Instance configurée
            """
            return Database(config)

        async def async_database_operation(db: Database, operation_func, *args, **kwargs):
            """
            Exécute une opération de base de données de manière asynchrone

            Args:
                db: Instance de base de données
                operation_func: Fonction à exécuter
                *args, **kwargs: Arguments pour la fonction

            Returns:
                Résultat de l'opération
            """
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, operation_func, *args, **kwargs)

        if __name__ == "__main__":
            # Tests et exemples d'utilisation
            def test_database():
                print("Test du gestionnaire de base de données")

                # Créer une base de données de test
                config = {
                    "database_path": "test_database.db",
                    "backup_enabled": True,
                    "cache_size": 5000
                }

                with Database(config) as db:
                    # Créer les tables
                    db.create_tables()
                    print("✅ Tables créées")

                    # Test d'insertion
                    test_data = {
                        "scan_id": "test_scan_001",
                        "target": "192.168.1.100",
                        "scan_type": "quick",
                        "status": "completed"
                    }

                    scan_id = db.insert("scans", test_data)
                    print(f"✅ Scan inséré: ID {scan_id}")

                    # Test de sélection
                    scans = db.select("scans", where={"target": "192.168.1.100"})
                    print(f"✅ Scans trouvés: {len(scans)}")

                    # Test des statistiques
                    stats = db.get_stats()
                    print(f"✅ Statistiques: {stats['total_queries']} requêtes")

                    # Test de santé
                    health = db.health_check()
                    print(f"✅ Santé: {'OK' if health['healthy'] else 'KO'}")

                    # Test de sauvegarde
                    backup_file = db.backup()
                    print(f"✅ Sauvegarde: {backup_file}")

                print("Test terminé avec succès")

            test_database()