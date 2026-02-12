"""
Tests end-to-end basiques pour valider le flux MVP :

1. Register → organisation + admin user
2. Login → JWT
3. CRUD asset (create + list)
4. Créer un scan (v1) sur l'asset
"""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

from src.api.main import app


@pytest.fixture(scope="session")
def client() -> TestClient:
    # S'assurer que la clé JWT est définie pour les tests
    os.environ.setdefault("JWT_SECRET_KEY", "test_jwt_secret_key_for_e2e")
    return TestClient(app)


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_e2e_register_login_asset_and_scan(client: TestClient) -> None:
    # 1. Register
    email = f"e2e-{uuid.uuid4().hex[:8]}@example.com"
    password = "TestPassword123!"
    org_name = f"E2E Org {uuid.uuid4().hex[:4]}"

    register_payload = {
        "email": email,
        "password": password,
        "full_name": "E2E User",
        "organization_name": org_name,
    }
    r = client.post("/auth/register", json=register_payload)
    assert r.status_code == 201, r.text
    user_data = r.json()
    assert user_data["email"] == email

    # 2. Login pour récupérer le token JWT
    login_data = {"username": email, "password": password}
    r = client.post("/auth/login", data=login_data)
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    assert token

    # 3. Créer un asset
    asset_payload = {
        "hostname": "e2e-server",
        "ip_address": "10.0.0.10",
        "asset_type": "server",
        "environment": "test",
        "business_criticality": "medium",
        "tags": ["e2e", "test"],
        "notes": "Asset créé par test_e2e",
    }
    r = client.post("/api/v1/assets", json=asset_payload, headers=_headers(token))
    assert r.status_code == 201, r.text
    asset = r.json()
    assert asset["ip_address"] == "10.0.0.10"
    asset_id = asset["id"]

    # 4. Vérifier que l'asset apparaît dans la liste
    r = client.get("/api/v1/assets", headers=_headers(token))
    assert r.status_code == 200, r.text
    assets = r.json()
    assert any(a["id"] == asset_id for a in assets)

    # 5. Créer un scan v1 sur cet asset
    scan_payload = {
        "asset_id": asset_id,
        "scan_type": "quick",
    }
    r = client.post("/api/v1/scans", json=scan_payload, headers=_headers(token))
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["asset_id"] == asset_id
    assert scan["scan_type"] == "quick"

