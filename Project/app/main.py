from typing import Protocol
from fastapi import FastAPI, HTTPException, Depends, status
from enum import Enum
from sqlalchemy import Engine
from sqlalchemy.orm import Session
import os
from jose import jwt
from dataclasses import dataclass    
import app.models as models
from app.database import engine, SessionLocal
from organisationRepo import OrganisationRepository
from teacherRepo import TeacherRepository
from app.schemas import Organisation, Teacher

app = FastAPI()
models.Base.metadata.create_all(bind=engine)



@dataclass
class APIResponse:
    data: dict
    status: int = 200




def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# No need for db_dependency annotation
def db_dependency():
    return Depends(get_db)


@app.get("/")
async def root():
    return {"message": "Welcome to the API, made with FastAPI!!"}

#ORGANISATION
@app.post("/organisation/add")
async def create_organisation(organisation: Organisation):
    try:
        repo = OrganisationRepository(engine)
        repo.create_organisation(organisation)
        return {"message": "Organisation created successfully"}
    except Exception as e:
        # Log the error if needed
        # logger.error("An error occurred while creating an item: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")
#TEACHER
@app.post("/teacher/add")
async def create_teacher(teacher: Teacher):
    try:
        repo = TeacherRepository(engine)
        repo.create_teacher(teacher)
        return {"message": "Teacher created successfully"}
    except Exception as e:
        # Log the error if needed
        # logger.error("An error occurred while creating an item: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")