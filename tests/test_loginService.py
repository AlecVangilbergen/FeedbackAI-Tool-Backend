from dataclasses import dataclass, field
from typing import List, Optional

import bcrypt
from pydantic import EmailStr
from app.schemas import UserRole
from app.Submission.Service.loginService import AuthService, UserReadModel
import pytest

@dataclass
class MockUserRepository:
    users: List[UserReadModel] = field(default_factory=list)

    async def get_user_by_name(self, username: str) -> Optional[UserReadModel]:
        for user in self.users:
            if user.username == username:
                return user
        return None

    async def get_user_by_email(self, email: EmailStr) -> Optional[UserReadModel]:
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
    repo.users.append(UserReadModel(
        username="test",
        firstname="test",
        lastname="test",
        email="test@gmail.com",
        hashed_password=hashed_pw,
        role=UserRole.STUDENT
    ))
    
    service = AuthService(repo)
    maybe_user = await service.authenticate_user("test", "test", UserRole.STUDENT)
    assert maybe_user is not None

@pytest.mark.asyncio
async def test_fail_authentication_if_user_exists_and_password_different():
    repo = MockUserRepository()
    hashed_pw = repo.get_hashed_password("test")
    repo.users.append(UserReadModel(
        username="test",
        firstname="test",
        lastname="test",
        email="test@gmail.com",
        hashed_password=hashed_pw,
        role=UserRole.STUDENT
    ))
    
    service = AuthService(repo)
    maybe_user = await service.authenticate_user("test", "te", UserRole.STUDENT)
    assert maybe_user is None

@pytest.mark.asyncio
async def test_fail_authentication_if_user_doesnt_exist():
    repo = MockUserRepository()
    service = AuthService(repo)
    maybe_user = await service.authenticate_user("test2", "test", UserRole.STUDENT)
    assert maybe_user is None

@pytest.mark.asyncio
async def test_register_user_successfully():
    repo = MockUserRepository()
    service = AuthService(repo)
    new_user = await service.register_user("new_user", "test", "test", "new_user@gmail.com", "new_password", UserRole.STUDENT)
    assert new_user is not None
    assert new_user.username == "new_user"
    assert new_user.email == "new_user@gmail.com"
    assert await service.authenticate_user("new_user", "new_password", UserRole.STUDENT) is not None

@pytest.mark.asyncio
async def test_register_user_fail_if_email_exists():
    repo = MockUserRepository()
    hashed_pw = repo.get_hashed_password("existing_password")
    repo.users.append(UserReadModel(
        username="existing_user",
        firstname="test",
        lastname="test",
        email="existing@gmail.com",
        hashed_password=hashed_pw,
        role=UserRole.STUDENT
    ))
    
    service = AuthService(repo)
    with pytest.raises(ValueError) as exc_info:
        await service.register_user("new_user", "test", "test", "existing@gmail.com", "new_password", UserRole.STUDENT)
    assert str(exc_info.value) == "Email already registered"

@pytest.mark.asyncio
async def test_authenticate_multiple_users():
    repo = MockUserRepository()
    hashed_pw_1 = repo.get_hashed_password("password1")
    hashed_pw_2 = repo.get_hashed_password("password2")
    repo.users.append(UserReadModel(
        username="user1",
        firstname="test",
        lastname="test",
        email="user1@gmail.com",
        hashed_password=hashed_pw_1,
        role=UserRole.STUDENT
    ))
    repo.users.append(UserReadModel(
        username="user2",
        firstname="test",
        lastname="test",
        email="user2@gmail.com",
        hashed_password=hashed_pw_2,
        role=UserRole.TEACHER
    ))
    
    service = AuthService(repo)
    user1 = await service.authenticate_user("user1", "password1", UserRole.STUDENT)
    user2 = await service.authenticate_user("user2", "password2", UserRole.TEACHER)
    assert user1 is not None
    assert user2 is not None
    assert user1.username == "user1"
    assert user2.username == "user2"

@pytest.mark.asyncio
async def test_authentication_fail_after_successful_registration_with_wrong_password():
    repo = MockUserRepository()
    service = AuthService(repo)
    await service.register_user("new_user", "test", "test", "new_user@gmail.com", "correct_password", UserRole.STUDENT)
    
    authenticated_user = await service.authenticate_user("new_user", "wrong_password", UserRole.STUDENT)
    assert authenticated_user is None
