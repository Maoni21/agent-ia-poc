.PHONY: help dev dev-backend dev-frontend install build test clean docker-up docker-down docker-build docker-logs docker-restart

# Couleurs pour les messages
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m # No Color

help: ## Affiche cette aide
	@echo "$(BLUE)=== Vulnerability Agent - Commandes disponibles ===$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# ============================================================================
# DÉVELOPPEMENT
# ============================================================================

dev: ## Lancer tout en développement (Docker Compose)
	@echo "$(BLUE)🚀 Démarrage de l'environnement de développement...$(NC)"
	docker-compose up

dev-backend: ## Lancer seulement le backend en développement
	@echo "$(BLUE)🔧 Démarrage du backend...$(NC)"
	cd backend && python -m venv .venv && \
	.venv/bin/pip install -r requirements.txt && \
	.venv/bin/uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend: ## Lancer seulement le frontend en développement
	@echo "$(BLUE)🎨 Démarrage du frontend...$(NC)"
	cd frontend && npm install && npm run dev

# ============================================================================
# INSTALLATION
# ============================================================================

install: install-backend install-frontend ## Installer toutes les dépendances

install-backend: ## Installer les dépendances backend
	@echo "$(BLUE)📦 Installation des dépendances backend...$(NC)"
	cd backend && \
	if [ ! -d ".venv" ]; then python -m venv .venv; fi && \
	.venv/bin/pip install --upgrade pip && \
	.venv/bin/pip install -r requirements.txt

install-frontend: ## Installer les dépendances frontend
	@echo "$(BLUE)📦 Installation des dépendances frontend...$(NC)"
	cd frontend && npm install

# ============================================================================
# BUILD
# ============================================================================

build: build-backend build-frontend ## Build tout pour la production

build-backend: ## Build le backend
	@echo "$(BLUE)🔨 Build du backend...$(NC)"
	cd backend && python -m pip install -r requirements.txt

build-frontend: ## Build le frontend pour la production
	@echo "$(BLUE)🔨 Build du frontend...$(NC)"
	cd frontend && npm run build

# ============================================================================
# TESTS
# ============================================================================

test: test-backend test-frontend ## Lancer tous les tests

test-backend: ## Lancer les tests backend
	@echo "$(BLUE)🧪 Tests backend...$(NC)"
	@if [ -d ".venv" ]; then \
		.venv/bin/python -m pytest backend/tests/ -v; \
	elif [ -d "backend/.venv" ]; then \
		cd backend && .venv/bin/pytest -v tests/; \
	else \
		cd backend && pytest -v tests/; \
	fi

test-frontend: ## Lancer les tests frontend
	@echo "$(BLUE)🧪 Tests frontend...$(NC)"
	cd frontend && npm test

# ============================================================================
# DOCKER
# ============================================================================

docker-up: ## Démarrer tous les services Docker
	@echo "$(BLUE)🐳 Démarrage des containers Docker...$(NC)"
	docker-compose up -d

docker-down: ## Arrêter tous les services Docker
	@echo "$(BLUE)🛑 Arrêt des containers Docker...$(NC)"
	docker-compose down

docker-build: ## Build les images Docker
	@echo "$(BLUE)🔨 Build des images Docker...$(NC)"
	docker-compose build

docker-logs: ## Voir les logs Docker
	docker-compose logs -f

docker-restart: ## Redémarrer tous les services Docker
	@echo "$(BLUE)🔄 Redémarrage des containers Docker...$(NC)"
	docker-compose restart

docker-clean: ## Nettoyer les containers et volumes Docker
	@echo "$(YELLOW)⚠️  Nettoyage des containers Docker...$(NC)"
	docker-compose down -v
	docker system prune -f

# ============================================================================
# NETTOYAGE
# ============================================================================

clean: clean-backend clean-frontend clean-docker ## Nettoyer tout

clean-backend: ## Nettoyer le backend (cache Python, etc.)
	@echo "$(BLUE)🧹 Nettoyage backend...$(NC)"
	find backend -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find backend -type f -name "*.pyc" -delete 2>/dev/null || true
	find backend -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf backend/.venv backend/dist backend/build 2>/dev/null || true

clean-frontend: ## Nettoyer le frontend (node_modules, build, etc.)
	@echo "$(BLUE)🧹 Nettoyage frontend...$(NC)"
	rm -rf frontend/node_modules frontend/.next frontend/out frontend/build 2>/dev/null || true
	rm -f frontend/npm-debug.log* frontend/yarn-debug.log* frontend/yarn-error.log* 2>/dev/null || true

clean-docker: ## Nettoyer les images Docker
	@echo "$(BLUE)🧹 Nettoyage Docker...$(NC)"
	docker-compose down -v --rmi all 2>/dev/null || true

# ============================================================================
# BASE DE DONNÉES
# ============================================================================

db-migrate: ## Lancer les migrations de base de données
	@echo "$(BLUE)🗄️  Migration de la base de données...$(NC)"
	cd backend && \
	if [ -d ".venv" ]; then \
		.venv/bin/alembic upgrade head; \
	else \
		alembic upgrade head; \
	fi

db-reset: ## Réinitialiser la base de données (⚠️  DANGEREUX)
	@echo "$(YELLOW)⚠️  Réinitialisation de la base de données...$(NC)"
	docker-compose exec db psql -U vulnagent -d vulnerability_db -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# ============================================================================
# UTILITAIRES
# ============================================================================

setup: install ## Configuration initiale complète
	@echo "$(GREEN)✅ Configuration terminée !$(NC)"
	@echo "$(BLUE)📝 N'oubliez pas de créer les fichiers .env :$(NC)"
	@echo "   - cp .env.example .env"
	@echo "   - cp backend/.env.example backend/.env"
	@echo "   - cp frontend/.env.example frontend/.env.local"

status: ## Afficher le statut des services
	@echo "$(BLUE)📊 Statut des services:$(NC)"
	@docker-compose ps || echo "Docker Compose n'est pas en cours d'exécution"
	@echo ""
	@echo "$(BLUE)🔍 Vérification des ports:$(NC)"
	@netstat -an | grep -E ":(3000|8000|5432)" || echo "Aucun service détecté sur les ports 3000, 8000, 5432"

logs-backend: ## Voir les logs du backend
	docker-compose logs -f backend

logs-frontend: ## Voir les logs du frontend
	docker-compose logs -f frontend

logs-db: ## Voir les logs de la base de données
	docker-compose logs -f db
