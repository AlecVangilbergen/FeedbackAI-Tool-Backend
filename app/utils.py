import os
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Union, Any
import jwt

ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
ALGORITHM = "HS256"
JWT_SECRET_KEY = "narscbjim@$@&^@&%^&RFghgjvbdsha"   # should be kept secret
JWT_REFRESH_SECRET_KEY = "13ugfdfgh@#$%^@&jkl45678902"
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def get_hashed_password(password: str) -> str:
    return password_context.hash(password)
def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)
def create_access_token(subject: Union[str, Any]) -> str:
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expires_at = datetime.utcnow() + expires_delta
    to_encode = {"exp": expires_at, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt

def create_refresh_token(subject: Union[str, Any]) -> str:
    expires_delta = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    expires_at = datetime.utcnow() + expires_delta
    to_encode = {"exp": expires_at, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt
def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user
