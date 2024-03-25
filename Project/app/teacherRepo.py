from dataclasses import dataclass
from app.models import Teacher
from app.schemas import CreateTeacher, Teacher as TeacherSchema
from sqlalchemy import select
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@dataclass
class TeacherRepository:
    session: AsyncSession
    
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_teacher(self, teacher: CreateTeacher) -> Teacher:
        hashed_password = pwd_context.hash(teacher.password)
        new_teacher = Teacher(name=teacher.name, lastname=teacher.lastname, email=teacher.email, password=hashed_password, organisation_id=teacher.organisation_id)
        self.session.add(new_teacher)
        await self.session.commit()
        return new_teacher
    
    async def get_teachers(self) -> List[TeacherSchema]:
        result = await self.session.execute(select(Teacher))
        teachers = [TeacherSchema.from_orm(teacher) for teacher in result.scalars()]
        return teachers
        
