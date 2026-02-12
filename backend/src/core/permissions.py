"""
RBAC et permissions pour la plateforme (Phase 1 – Semaine 2).

Implémente le dictionnaire ROLES_PERMISSIONS du cahier des charges et
quelques utilitaires simples pour le RBAC côté backend.
"""

from __future__ import annotations

from typing import Dict, List, Set

ROLES_PERMISSIONS: Dict[str, Dict[str, object]] = {
    "admin": {
        "description": "Accès complet à l'organization",
        "permissions": [
            # Users
            "users:create",
            "users:read",
            "users:update",
            "users:delete",
            # Assets
            "assets:create",
            "assets:read",
            "assets:update",
            "assets:delete",
            # Scans
            "scans:create",
            "scans:read",
            "scans:update",
            "scans:delete",
            # Vulnerabilities
            "vulnerabilities:read",
            "vulnerabilities:update",
            "vulnerabilities:delete",
            # Remediation
            "remediation:create",
            "remediation:execute",
            "remediation:approve",
            # Organization
            "organization:update",
            "organization:billing",
            # API Keys
            "apikeys:create",
            "apikeys:read",
            "apikeys:revoke",
        ],
    },
    "manager": {
        "description": "Gestionnaire de sécurité",
        "permissions": [
            "assets:create",
            "assets:read",
            "assets:update",
            "scans:create",
            "scans:read",
            "vulnerabilities:read",
            "vulnerabilities:update",
            "remediation:create",
            "remediation:approve",
        ],
    },
    "analyst": {
        "description": "Analyste sécurité",
        "permissions": [
            "assets:read",
            "scans:create",
            "scans:read",
            "vulnerabilities:read",
            "vulnerabilities:update",
            "remediation:create",
        ],
    },
    "viewer": {
        "description": "Lecture seule",
        "permissions": [
            "assets:read",
            "scans:read",
            "vulnerabilities:read",
        ],
    },
}


def get_role_permissions(role: str) -> Set[str]:
    """Retourne les permissions associées à un rôle."""
    base = ROLES_PERMISSIONS.get(role, {})
    return set(base.get("permissions", []))


def merge_permissions(role: str, custom_permissions: List[str] | None) -> Set[str]:
    """
    Construit l'ensemble final de permissions :
    - Permissions du rôle
    - + permissions personnalisées éventuelles (colonne users.permissions)
    """
    perms = get_role_permissions(role)
    if custom_permissions:
        perms.update(custom_permissions)
    return perms


def has_permission(role: str, permission: str, custom_permissions: List[str] | None) -> bool:
    """Vérifie si le rôle (avec permissions custom éventuelles) possède `permission`."""
    return permission in merge_permissions(role, custom_permissions)


__all__ = ["ROLES_PERMISSIONS", "get_role_permissions", "merge_permissions", "has_permission"]

