from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
import jwt

ALGORITHM = "HS256"
JWT_SECRET_KEY = "narscbjim@$@&^@&%^&RFghgjvbdsha"

app = FastAPI()

def generate_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        decoded_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        if decoded_token["exp"] < datetime.utcnow().timestamp():
            raise HTTPException(status_code=403, detail="Expired token.")
        return decoded_token
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=403, detail="Expired token.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail="Invalid token.")

class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        if credentials:
            if credentials.scheme != "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jwttoken: str) -> bool:
        isTokenValid: bool = False
        try:
            payload = jwt.decode(jwttoken, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=403, detail="Expired token.")
        except (jwt.InvalidTokenError, Exception):
            raise HTTPException(status_code=403, detail="Invalid token.")
        if payload:
            isTokenValid = True
        return isTokenValid