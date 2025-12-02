"""Application configuration profiles."""
from __future__ import annotations

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_URI = os.environ.get('DATABASE_URL', f"sqlite:///{os.path.join(BASE_DIR, 'app.db')}")


class BaseConfig:
    SQLALCHEMY_DATABASE_URI = DEFAULT_DB_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('FLASK_SECRET', 'dev-secret-key')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME', 'http')


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class TestingConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
}
