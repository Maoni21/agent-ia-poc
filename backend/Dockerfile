FROM python:3.10-slim

# Métadonnées
LABEL maintainer="CyberSec AI Team"
LABEL description="Backend FastAPI pour l'Agent IA de Cybersécurité"

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# Définir le répertoire de travail
WORKDIR /app

# Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    gcc \
    g++ \
    libpq-dev \
    libcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copier et installer les dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY . .

# Créer les répertoires nécessaires
RUN mkdir -p /app/data/database /app/data/workflow_results /app/logs

# Exposer le port
EXPOSE 8000

# Commande par défaut
CMD ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
