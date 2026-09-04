import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.factory import create_app
from app.database import db as _db


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    application = create_app(db_path=f"sqlite:///{path}", secret_key="test-secret")
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    yield application
    with application.app_context():
        _db.session.remove()
        _db.drop_all()
    os.remove(path)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def registered_client(client):
    client.post("/register", data={
        "username": "tester",
        "email": "tester@example.com",
        "password": "SuperSecret123",
    }, follow_redirects=True)
    return client
