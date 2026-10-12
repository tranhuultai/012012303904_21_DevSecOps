from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_root():
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["message"] == "DevSecOps Demo API"
    assert data["status"] == "running"


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_info():
    response = client.get("/api/info")

    assert response.status_code == 200

    data = response.json()

    assert data["application"] == "DevSecOps Demo"
    assert data["version"] == "1.0.0"


def test_create_user():
    payload = {
        "name": "Nguyen Van A",
        "email": "test@example.com",
    }

    response = client.post("/users", json=payload)

    assert response.status_code == 201

    data = response.json()

    assert data["message"] == "User created successfully"
    assert data["user"]["name"] == "Nguyen Van A"
    assert data["user"]["email"] == "test@example.com"


def test_create_user_invalid_payload():
    payload = {
        "name": "Nguyen Van A",
    }

    response = client.post("/users", json=payload)

    assert response.status_code == 422

def test_create_user_invalid_email():
    response = client.post(
        "/users",
        json={
            "name": "Nguyen Van A",
            "email": "not-an-email",
        },
    )
    assert response.status_code == 422