"""Tests de base"""
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_imports():
    """Test imports"""
    from src.core import Collector
    from src.database import Database
    from src.utils import setup_logger
    assert Collector is not None

def test_database():
    """Test database"""
    from src.database import Database
    db = Database({"database_path": ":memory:"})
    db.create_tables()
    assert db.is_initialized

def test_config():
    """Test config"""
    from config.settings import get_config
    config = get_config()
    assert config is not None

def test_validators():
    """Test validators"""
    from src.utils import validate_ip_address
    assert validate_ip_address("192.168.1.1")
    assert not validate_ip_address("999.999.999.999")
