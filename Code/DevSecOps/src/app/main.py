from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

app = FastAPI(
    title="DevSecOps Security Demo API",
    version="1.0.0",
    description="Application used for the DevSecOps security pipeline experiment.",
)


class UserRequest(BaseModel):
    name: str
    email: EmailStr


users_db: list[dict] = []


@app.get("/")
def root():
    return {
        "message": "DevSecOps Demo API",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/info")
def api_info():
    return {
        "application": "DevSecOps Demo",
        "version": "1.0.0",
        "environment": "lab",
    }


@app.post("/users", status_code=201)
def create_user(user: UserRequest):
    if any(existing["email"] == str(user.email) for existing in users_db):
        raise HTTPException(
            status_code=409,
            detail="Email already exists",
        )

    user_record = {
        "name": user.name,
        "email": str(user.email),
    }
    users_db.append(user_record)

    return {
        "message": "User created successfully",
        "user": user_record,
    }


@app.get("/users")
def list_users():
    return {"users": users_db}