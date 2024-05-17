import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import Request, HTTPException
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Generic, Optional
from datetime import datetime, timedelta

ALGORITHM = "HS256"

JWT_SECRET_KEY = "narscbjim@$@&^@&%^&RFghgjvbdsha"

def generate_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encode_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encode_jwt

def decode_token(token: str):
    try:
        decode_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        return decode_token if decode_token["expires"] >= datetime.utcnow() else None
    except:
        return{}

class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = super.__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")


    def verify_jwt(self, jwttoken: str):
        isTokenValid: bool = False
        try:

            payload = jwt.decode(jwttoken, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        except:
            payload = None
        if payload:
            isTokenValid = True
        return isTokenValid


