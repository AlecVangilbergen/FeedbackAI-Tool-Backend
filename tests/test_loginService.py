from dataclasses import dataclass, field
from typing import List

import bcrypt
from pydantic import EmailStr
from app.Submission.Service.loginService import AuthService, UserReadModel
import pytest

@dataclass
class MockUserRepository:
    users: List[UserReadModel] = field(default_factory=list)

    async def get_user_by_name(self, username: str) -> UserReadModel | None:
        for user in self.users:
            if user.username == username:
                return user
        return None

    async def get_user_by_email(self, email: EmailStr) -> UserReadModel | None:
        for user in self.users:
            if user.email == email:
                return user
        return None

    async def save_new_user(self, user: UserReadModel) -> None:
        self.users.append(user)

    def get_hashed_password(self, password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode("utf-8")

@pytest.mark.asyncio
async def test_authenticate_if_user_exists_and_password_same():
    repo = MockUserRepository()
    hashed_pw = repo.get_hashed_password("test")
    repo.users.append(UserReadModel("test","test","test", "test@gmail.com", hashed_pw))
    
    service = AuthService(repo)
    maybe_user = await service.authenticate_user("test", "test")
    assert maybe_user is not None

@pytest.mark.asyncio
async def test_fail_authentication_if_user_exists_and_password_different():
    repo = MockUserRepository()
    hashed_pw = repo.get_hashed_password("test")
    repo.users.append(UserReadModel("test", "test","test","test@gmail.com", hashed_pw))
    
    service = AuthService(repo)
    maybe_user = await service.authenticate_user("test", "te")
    assert maybe_user is None

@pytest.mark.asyncio
async def test_fail_authentication_if_user_doesnt_exist():
    repo = MockUserRepository()
    service = AuthService(repo)
    maybe_user = await service.authenticate_user("test2", "test")
    assert maybe_user is None

@pytest.mark.asyncio
async def test_register_user_successfully():
    repo = MockUserRepository()
    service = AuthService(repo)
    new_user = await service.register_user("new_user","test","test","new_user@gmail.com", "new_password", "user")
    assert new_user is not None
    assert new_user.username == "new_user"
    assert new_user.email == "new_user@gmail.com"
    assert await service.authenticate_user("new_user", "new_password") is not None

@pytest.mark.asyncio
async def test_register_user_fail_if_email_exists():
    repo = MockUserRepository()
    hashed_pw = repo.get_hashed_password("existing_password")
    repo.users.append(UserReadModel("existing_user","test","test", "existing@gmail.com", hashed_pw))
    
    service = AuthService(repo)
    with pytest.raises(ValueError) as exc_info:
        await service.register_user("new_user","test","test", "existing@gmail.com", "new_password", "user")
    assert str(exc_info.value) == "Email already registered"

@pytest.mark.asyncio
async def test_authenticate_multiple_users():
    repo = MockUserRepository()
    hashed_pw_1 = repo.get_hashed_password("password1")
    hashed_pw_2 = repo.get_hashed_password("password2")
    repo.users.append(UserReadModel("user1","test","test", "user1@gmail.com", hashed_pw_1))
    repo.users.append(UserReadModel("user2","test","test", "user2@gmail.com", hashed_pw_2))
    
    service = AuthService(repo)
    user1 = await service.authenticate_user("user1", "password1")
    user2 = await service.authenticate_user("user2", "password2")
    assert user1 is not None
    assert user2 is not None
    assert user1.username == "user1"
    assert user2.username == "user2"

@pytest.mark.asyncio
async def test_authentication_fail_after_successful_registration_with_wrong_password():
    repo = MockUserRepository()
    service = AuthService(repo)
    await service.register_user("new_user", "test","test","new_user@gmail.com", "correct_password", "user")
    
    authenticated_user = await service.authenticate_user("new_user", "wrong_password")
    assert authenticated_user is None