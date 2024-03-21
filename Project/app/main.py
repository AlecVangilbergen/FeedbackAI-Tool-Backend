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
from app.organisationRepo import OrganisationRepository
from app.studentRepo import StudentRepository
from app.teacherRepo import TeacherRepository
from app.adminRepo import AdminRepository
from app.schemas import Organisation, Teacher, CreateOrganisation, CreateTeacher, CreateStudent, Student, CreateAdmin, Admin

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


#ADMIN
@app.post("/admin/add")
async def create_admin(admin: CreateAdmin):
    try:
        repo = AdminRepository(engine)
        repo.create_admin(admin)
        return {"message": "Admin created successfully"}
    except Exception as e:
        # Log the error if needed
        # logger.error("An error occurred while creating an item: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/admins")
async def get_admins():
    try:
        repo = AdminRepository(engine)
        admins = repo.get_admins()
        return APIResponse(data=admins)
    except Exception as e:
        # Log the error if needed
        # logger.error("An error occurred while creating an item: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

#ORGANISATION

@app.post("/organisation/add")
async def create_organisation(organisation: CreateOrganisation):
    try:
        repo = OrganisationRepository(engine)
        repo.create_organisation(organisation)
        return {"message": "Organisation created successfully"}
    except Exception as e:
        # Log the error if needed
        # logger.error("An error occurred while creating an item: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/organisations")
async def get_organisations():
    try:
        repo = OrganisationRepository(engine)
        organisations = repo.get_organisations()
        return APIResponse(data=organisations)
    except Exception as e:
        # Log the error if needed
        # logger.error("An error occurred while creating an item: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

#TEACHER
@app.post("/teacher/add")
async def create_teacher(teacher: CreateTeacher):
    try:
        repo = TeacherRepository(engine)
        repo.create_teacher(teacher)
        return {"message": "Teacher created successfully"}
    except Exception as e:
        # Log the error if needed
        # logger.error("An error occurred while creating an item: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    

@app.get("/teachers")
async def get_teachers():
    try:
        repo = TeacherRepository(engine)
        teachers = repo.get_teachers()
        return APIResponse(data=teachers)
    except Exception as e:
        # Log the error if needed
        # logger.error("An error occurred while creating an item: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    
#STUDENT
@app.post("/student/add")
async def create_student(student: CreateStudent):
    try:
        repo = StudentRepository(engine)
        repo.create_student(student)
        return {"message": "Student created successfully"}
    except Exception as e:
        # Log the error if needed
        # logger.error("An error occurred while creating an item: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    

@app.get("/students")
async def get_students():
    try:
        repo = StudentRepository(engine)
        students = repo.get_students()
        return APIResponse(data=students)
    except Exception as e:
        # Log the error if needed
        # logger.error("An error occurred while creating an item: %s", e)
        raise HTTPException(status_code=500, detail=str(e))