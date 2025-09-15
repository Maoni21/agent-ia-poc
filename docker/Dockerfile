# Dockerfile pour Agent IA de Cybersécurité
# Version: 1.0.0
# Base: Python 3.11 Alpine pour une image légère

# === ÉTAPE 1: IMAGE DE BASE ===
ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-alpine as base

# Métadonnées
LABEL maintainer="Agent IA Cybersécurité <security@company.com>"
LABEL version="1.0.0"
LABEL description="Agent IA pour la détection et correction de vulnérabilités"
LABEL org.opencontainers.image.source="https://github.com/company/vulnerability-agent"

# Variables d'environnement Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# === ÉTAPE 2: DÉPENDANCES SYSTÈME ===
FROM base as system-deps

# Mise à jour des packages et installation des dépendances système
RUN apk update && apk upgrade && \
    apk add --no-cache \
    # Outils de base
    curl \
    wget \
    git \
    # Compilation Python
    gcc \
    musl-dev \
    libffi-dev \
    # Nmap et outils réseau
    nmap \
    nmap-scripts \
    # OpenSSL pour HTTPS
    openssl \
    openssl-dev \
    # Outils système
    procps \
    && rm -rf /var/cache/apk/*

# === ÉTAPE 3: UTILISATEUR NON-ROOT ===
FROM system-deps as user-setup

# Créer un utilisateur non-root pour la sécurité
RUN addgroup -g 1000 appgroup && \
    adduser -D -s /bin/sh -u 1000 -G appgroup appuser

# Créer les répertoires de travail
RUN mkdir -p /app /app/data /app/logs /app/config && \
    chown -R appuser:appgroup /app

# === ÉTAPE 4: DÉPENDANCES PYTHON ===
FROM user-setup as python-deps

# Passer à l'utilisateur non-root
USER appuser
WORKDIR /app

# Copier les fichiers de dépendances
COPY --chown=appuser:appgroup requirements.txt ./

# Mise à jour pip et installation des dépendances Python
RUN pip install --upgrade pip && \
    pip install --user --no-cache-dir -r requirements.txt

# === ÉTAPE 5: APPLICATION ===
FROM python-deps as app

# Variables d'environnement pour l'application
ENV PATH="/home/appuser/.local/bin:${PATH}" \
    PYTHONPATH="/app" \
    APP_ENV=production \
    LOG_LEVEL=INFO \
    DATABASE_PATH=/app/data/database/vulnerability_agent.db

# Copier le code source (en respectant .dockerignore)
COPY --chown=appuser:appgroup . .

# Créer les répertoires nécessaires
RUN mkdir -p data/scans data/reports data/scripts data/database logs

# === ÉTAPE 6: CONFIGURATION DE SÉCURITÉ ===
FROM app as security

# Vérifications de sécurité
RUN python -c "import ssl; print('SSL OK')" && \
    python -c "import sqlite3; print('SQLite OK')" && \
    python -c "import nmap; print('python-nmap OK')" && \
    nmap --version

# Permissions strictes
RUN chmod -R 755 /app && \
    chmod -R 750 /app/data /app/logs && \
    chmod +x /app/main.py

# === ÉTAPE 7: HEALTHCHECK ===
FROM security as final

# Configuration du healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Exposition des ports
EXPOSE 8000 8080

# Point de montage pour les volumes
VOLUME ["/app/data", "/app/logs"]

# Script d'entrée personnalisé
COPY --chown=appuser:appgroup docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Commande par défaut
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "main.py", "--api", "--host", "0.0.0.0", "--port", "8000"]

# === DOCKERFILE MULTI-STAGE POUR DÉVELOPPEMENT ===
FROM final as development

USER root

# Outils de développement supplémentaires
RUN apk add --no-cache \
    vim \
    nano \
    htop \
    strace \
    tcpdump \
    && rm -rf /var/cache/apk/*

# Dépendances Python de développement
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    black \
    flake8 \
    mypy \
    ipython \
    jupyter

# Retour à l'utilisateur non-root
USER appuser

# Variables de développement
ENV APP_ENV=development \
    LOG_LEVEL=DEBUG \
    PYTHONDONTWRITEBYTECODE=0

# Commande de développement avec reload automatique
CMD ["python", "main.py", "--dev", "--reload"]

# === DOCKERFILE POUR SCANNER SÉPARÉ ===
FROM alpine:latest as scanner

# Installation de Nmap uniquement
RUN apk update && \
    apk add --no-cache \
    nmap \
    nmap-scripts \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/*

# Installation python-nmap
RUN pip3 install --no-cache-dir python-nmap requests

# Utilisateur scanner
RUN adduser -D -s /bin/sh scanner
USER scanner

# Script de scan
COPY --chown=scanner:scanner docker/scanner.py /scanner.py
RUN chmod +x /scanner.py

# Commande par défaut
ENTRYPOINT ["python3", "/scanner.py"]

# === BUILD ARGS ET MÉTADONNÉES FINALES ===
FROM final

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=1.0.0

# Métadonnées étendues
LABEL org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.title="Vulnerability Agent" \
      org.opencontainers.image.description="Agent IA pour la détection et correction de vulnérabilités de sécurité" \
      org.opencontainers.image.vendor="Security Team" \
      org.opencontainers.image.licenses="MIT"

# Instructions de build
# docker build -f docker/Dockerfile -t vulnerability-agent:latest .
# docker build -f docker/Dockerfile --target development -t vulnerability-agent:dev .
# docker build -f docker/Dockerfile --target scanner -t vulnerability-scanner:latest .