from dataclasses import dataclass

import bcrypt
from app.Submission.Service.loginService import AuthService, UserReadModel
from passlib.context import CryptContext
import pytest
  

@dataclass
class MockUserRepository:

    async def get_user_by_name(self, username: str) -> UserReadModel | None:
        if username == "test":
            hashed_pw = self.get_hashed_password("test")
            return UserReadModel("test", "test@gmail.com", hashed_pw)
        else:
            return None
        
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