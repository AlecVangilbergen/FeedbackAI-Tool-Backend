from dataclasses import dataclass
import logging
from typing import Optional, cast, Protocol, Self
import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext
from app.models import User


@dataclass
class UserReadModel:
    username: str
    hashed_password: str


class IUserRepository(Protocol):

    async def get_user_by_name(self, username: str) -> UserReadModel | None:
        ...

    async def get_user_by_email(self, username: str) -> UserReadModel | None:
        ...
        
@dataclass
class UserRepository:
    session: AsyncSession

    async def get_user_by_name(self, username: str) -> UserReadModel | None:
        query = select(User).where(User.username == username)
        result = await self.session.execute(query)
        maybe_user = result.scalars().first()
        if maybe_user:
            username = cast(str, maybe_user.username)
            pw = cast(str, maybe_user.hashed_password)
            return UserReadModel(username, pw)
        
    async def get_user_by_email(self, username: str) -> UserReadModel | None:
        ...
    
    async def save_new_user()


@dataclass
class AuthService:
    user_repo: IUserRepository


    async def authenticate_user(self, username: str, password: str) -> Optional[UserReadModel]:
        logging.info(f"Authenticating user: {username}")
        user = await self.user_repo.get_user_by_name(username)
        if user:
            hashed_pw = cast(str, user.hashed_password)
            logging.info(f"User found: {user.username}")
            if self.verify_password(password, hashed_pw): 
                logging.info("Password verification successful")
                return user
            else:
                logging.info("Password verification failed")
        else:
            logging.info("User not found")
        return None
    
    async def register_user(self):
        ...
    
    @classmethod
    def from_session(cls, session: AsyncSession) -> Self:
        user_repo = UserRepository(session)
        return cls(user_repo)
    
    def verify_password(self, password: str, hashed_pass: str) -> bool:
        return bcrypt.checkpw(str.encode(password), str.encode(hashed_pass))
