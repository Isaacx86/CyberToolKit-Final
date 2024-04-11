import pytest
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from app import app as flask_app
from app.models import db as _db

TEST_DATABASE_URI = 'postgresql://localhost/test_db'

@pytest.fixture
def app():
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = TEST_DATABASE_URI
    yield flask_app

@pytest.fixture
def db(app, request):
    with app.app_context():
        _db.create_all()

    def teardown():
        _db.drop_all()

    request.addfinalizer(teardown)

    return _db

@pytest.fixture
def client(app):
    return app.test_client()
