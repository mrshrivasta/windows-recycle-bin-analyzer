def test_register_creates_user_and_logs_in(client):
    resp = client.post("/register", data={
        "username": "alice",
        "email": "alice@example.com",
        "password": "StrongPass123",
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data


def test_duplicate_username_rejected(registered_client):
    registered_client.get("/logout")
    resp = registered_client.post("/register", data={
        "username": "tester",
        "email": "other@example.com",
        "password": "AnotherPass123",
    }, follow_redirects=True)
    assert b"already registered" in resp.data


def test_login_wrong_password_rejected(registered_client):
    registered_client.get("/logout")
    resp = registered_client.post("/login", data={
        "username": "tester",
        "password": "wrongpassword",
    }, follow_redirects=True)
    assert b"Invalid username or password" in resp.data


def test_dashboard_requires_login(client):
    resp = client.get("/", follow_redirects=True)
    assert b"Login" in resp.data
