from dataclasses import dataclass
import logging
from typing import Optional, cast, Protocol, Self
import bcrypt
from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import User


@dataclass
class UserReadModel:
    username: str
    firstname: str
    lastname: str
    email: EmailStr
    hashed_password: str


class IUserRepository(Protocol):

    async def get_user_by_name(self, username: str) -> UserReadModel | None:
        ...

    async def get_user_by_email(self, email: EmailStr) -> UserReadModel | None:
        ...
    async def save_new_user(self, user: User) -> None:
        ...
        
@dataclass
class UserRepository:
    session: AsyncSession

    async def get_user_by_name(self, username: str) -> Optional[UserReadModel]:
        query = select(User).where(User.username == username)
        result = await self.session.execute(query)
        maybe_user = result.scalars().first()
        if maybe_user:
            return UserReadModel(
                username=cast(str, maybe_user.username),
                firstname=cast(str, maybe_user.firstname),
                lastname=cast(str, maybe_user.lastname),
                email=cast(EmailStr, maybe_user.email),
                hashed_password=cast(str, maybe_user.hashed_password)
            )
        return None
        
    async def get_user_by_email(self, email: EmailStr) -> Optional[UserReadModel]:
        query = select(User).where(User.email == email)
        result = await self.session.execute(query)
        maybe_user = result.scalars().first()
        if maybe_user:
            return UserReadModel(
                username=cast(str, maybe_user.username),
                firstname=cast(str, maybe_user.firstname),
                lastname=cast(str, maybe_user.lastname),
                email=cast(EmailStr, maybe_user.email),
                hashed_password=cast(str, maybe_user.hashed_password)
            )
        return None

    async def save_new_user(self, user: User) -> None:
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)



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
    
    async def register_user(self, username: str, firstname: str, lastname: str, email: EmailStr, password: str, role: str) -> UserReadModel:
        existing_user = await self.user_repo.get_user_by_email(email)
        if existing_user:
            raise ValueError("Email already registered")

        hashed_password = self.hash_password(password)
        new_user = User(
            username=username,
            firstname=firstname,
            lastname=lastname,
            email=email,
            hashed_password=hashed_password,
            role=role
        )
        await self.user_repo.save_new_user(new_user)
        
        return UserReadModel(
            username=username,
            firstname=firstname,
            lastname=lastname,
            email=email,
            hashed_password=hashed_password
        )
    
    
    
    @classmethod
    def from_session(cls, session: AsyncSession) -> Self:
        user_repo = UserRepository(session)
        return cls(user_repo)
    def verify_password(self, password: str, hashed_pass: str) -> bool:
        return bcrypt.checkpw(str.encode(password), str.encode(hashed_pass))
    def hash_password(self, password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
