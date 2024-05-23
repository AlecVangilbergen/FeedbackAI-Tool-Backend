from dataclasses import dataclass, field
from typing import List

import bcrypt
from pydantic import EmailStr
from app.Submission.Service.loginService import AuthService, UserReadModel
from passlib.context import CryptContext
import pytest
  

@dataclass
class MockUserRepository:
    users: List[UserReadModel] = field(default_factory=list)

    async def get_user_by_name(self, username: str) -> UserReadModel | None:
        if username == "test":
            hashed_pw = self.get_hashed_password("test")
            return UserReadModel("test", "test@gmail.com", hashed_pw)
        else:
            return None
    async def get_user_by_email(self, email: EmailStr) -> UserReadModel | None:
        for user in self.users:
            if user.email == email:
                return user
        return None

    async def save_new_user(self, user: UserReadModel) -> None:
        self.users.append(user)
        
    def get_hashed_password(self, password: str) -> str:
        return bcrypt.hashpw(str.encode(password), bcrypt.gensalt()).decode("utf-8")


@pytest.mark.asyncio
async def test_authenticate_if_user_exists_and_password_same():
    repo = MockUserRepository()
    service = AuthService(repo)
    maybe_user = await service.authenticate_user("test", "test")
    assert maybe_user is not None 


@pytest.mark.asyncio
async def test__fail_authentication__if_user_exists_and_password_different():
    repo = MockUserRepository()
    service = AuthService(repo)
    maybe_user = await service.authenticate_user("test", "te")
    assert maybe_user is None 

@pytest.mark.asyncio
async def test__fail_authentication__if_user_doesnt_exist():
    repo = MockUserRepository()
    service = AuthService(repo)
    maybe_user = await service.authenticate_user("test2", "test")
    assert maybe_user is None 

@pytest.mark.asyncio
async def test_register_user_successfully():
    repo = MockUserRepository()
    service = AuthService(repo)
    new_user = await service.register_user("new_user", "new_user@gmail.com", "new_password", "user")
    assert new_user is not None
    assert new_user.username == "new_user"
    assert new_user.email == "new_user@gmail.com"
    assert await service.authenticate_user("new_user", "new_password") is not None

@pytest.mark.asyncio
async def test_register_user_fail_if_email_exists():
    repo = MockUserRepository()
    hashed_pw = repo.get_hashed_password("existing_password")
    repo.users.append(UserReadModel("existing_user", "existing@gmail.com", hashed_pw))
    service = AuthService(repo)
    with pytest.raises(ValueError) as exc_info:
        await service.register_user("new_user", "existing@gmail.com", "new_password", "user")
    assert str(exc_info.value) == "Email already registered"