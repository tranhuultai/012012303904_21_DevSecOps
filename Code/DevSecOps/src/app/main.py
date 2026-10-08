from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI(
    title="DevSecOps Security Demo API",
    version="1.0.0",
    description="Application used for the DevSecOps security pipeline experiment.",
)


class UserRequest(BaseModel):
    name: str
    email: str


@app.get("/")
def root():
    return {
        "message": "DevSecOps Demo API",
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
    }


@app.get("/api/info")
def api_info():
    return {
        "application": "DevSecOps Demo",
        "version": "1.0.0",
        "environment": "lab",
    }


@app.post("/users")
def create_user(user: UserRequest):
    return {
        "message": "User created successfully",
        "user": {
            "name": user.name,
            "email": user.email,
        },
    }