from pydantic import BaseModel
from typing import Optional, List


# Command models for creating/updating data
class CreateOrganisation(BaseModel):
    name: str
    username: str
    password: str


class CreateAdmin(BaseModel):
    username: str
    password: str

class CreateTeacher(BaseModel):
    name: str
    lastname: str
    email: str
    password: str
    organisation_id: int


class CreateStudent(BaseModel):
    name: str
    lastname: str
    email: str
    password: str
    organisation_id: int


class CreateAssignment(BaseModel):
    name: str
    teacher_id: int
    template_contents: List[str]


class CreateTemplate(BaseModel):
    assignment_id: int
    template_content: str

class CreateCourse(BaseModel):
    name: str
    teacher_id: int


# Query models for retrieving data
class Organisation(BaseModel):
    id: int
    name: str
    username: str

    class Config:
        orm_mode = True
        from_orm = True
        from_attributes=True

    
class Admin(BaseModel):
    id: int
    role: str
    username: str

    class Config:
        orm_mode = True
        from_orm = True
        from_attributes=True


class Teacher(BaseModel):
    id: int
    name: str
    lastname: str
    email: str
    organisation_id: int

    class Config:
        orm_mode = True
        from_attributes = True
        from_orm = True

class Student(BaseModel):
    id: int
    name: str
    lastname: str
    email: str
    password: str
    organisation_id: int

    class Config:
        orm_mode = True


class Course(BaseModel):
    id: int
    name: str
    teacher_id: int

    class Config:
        orm_mode = True
        from_attributes = True


class Assignment(BaseModel):
    id: int
    name: str
    teacher_id: int
    templates: List["Template"] = []

    class Config:
        orm_mode = True


class Template(BaseModel):
    id: int
    content: str
    assignment_id: int

    class Config:
        orm_mode = True


class Submission(BaseModel):
    id: int
    content: str
    assignment_id: int
    student_id: int

    class Config:
        orm_mode = True


class Feedback(BaseModel):
    id: int
    content: str
    submission_id: int

    class Config:
        orm_mode = True

#Update models
class UpdateTeacher(BaseModel):
    name: Optional[str] = None
    lastname: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    organisation_id: Optional[int] = None