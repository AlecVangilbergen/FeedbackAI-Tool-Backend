import os
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, Union, Any
import jwt
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import SessionLocal, async_engine, Base
from app.models import User 

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

async def get_user(db: AsyncSession, username: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.username == username))
    return result.scalars().first()

async def authenticate_user(db: AsyncSession, username: str, password: str) -> Optional[User]:
    user = await get_user(db, username)
    if not user or not verify_password(password, user.password):  # Ensure the actual password value is accessed
        return None
    return user