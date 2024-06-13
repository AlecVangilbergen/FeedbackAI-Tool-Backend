from sqlalchemy import TIMESTAMP, Boolean, UniqueConstraint, create_engine, Column, Integer, String, ForeignKey, Text, DateTime
from sqlalchemy.orm import sessionmaker, relationship, Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from app.database import async_engine, Base
from datetime import datetime, timezone
from sqlalchemy import event

from app.schemas import UserRole

class Organisation(Base):
    __tablename__ = "organisations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default="organisation")
    teachers = relationship("Teacher", back_populates="organisation")
    students = relationship("Student", back_populates="organisation")

class Teacher(Base):
    __tablename__ = "teachers"

    id = Column(Integer, primary_key=True, index=True)
    organisation_id = Column(Integer, ForeignKey("organisations.id"), nullable=False)
    name = Column(String, nullable=False)
    lastname = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default="teacher")
    organisation = relationship("Organisation", back_populates="teachers")
    courses = relationship("Course", back_populates="teacher", cascade="all, delete-orphan")

class Student(Base):
    __tablename__ = "students"

    id = Column(Integer, primary_key=True, index=True)
    organisation_id = Column(Integer, ForeignKey("organisations.id"), nullable=False)
    name = Column(String, nullable=False)
    lastname = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default="student")
    organisation = relationship("Organisation", back_populates="students")
    submissions = relationship("Submission", back_populates="student")

class Course(Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True, index=True)
    teacher_id = Column(Integer, ForeignKey("teachers.id"), nullable=False)
    name = Column(String, nullable=False)
    teacher = relationship("Teacher", back_populates="courses")
    assignments = relationship("Assignment", back_populates="course")
    UniqueConstraint("name", "teacher_id", name="Unique_Course_name_From_Teacher")

class Assignment(Base):
    __tablename__ = "assignments"

    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("courses.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    word_count = Column(Integer, nullable=False)
    student_ages = Column(Integer, nullable=False)
    course = relationship("Course", back_populates="assignments")
    templates = relationship("Template", back_populates="assignment")
    submissions = relationship("Submission", back_populates="assignment")
    UniqueConstraint("course_id, title", name="Unique_Assignment_Title_Per_Course")

class Template(Base):
    __tablename__ = "templates"

    id = Column(Integer, primary_key=True, index=True)
    assignment_id = Column(Integer, ForeignKey("assignments.id"), nullable=False)
    content = Column(Text, nullable=False)
    assignment = relationship("Assignment", back_populates="templates")

class Submission(Base):
    __tablename__ = "submissions"

    id = Column(Integer, primary_key=True, index=True)
    assignment_id = Column(Integer, ForeignKey("assignments.id"), nullable=False)
    student_id = Column(Integer, ForeignKey("students.id"), nullable=False)
    date_created = Column(TIMESTAMP(timezone=True), default=datetime.now(timezone.utc))
    content = Column(Text, nullable=False)
    assignment = relationship("Assignment", back_populates="submissions")
    student = relationship("Student", back_populates="submissions")
    feedback = relationship("Feedback", uselist=False, back_populates="submission")

class Feedback(Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False)
    content = Column(Text, nullable=False)
    submission = relationship("Submission", back_populates="feedback")

class Admin(Base):
    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(unique=True, nullable=False, index=True)
    password: Mapped[str] = mapped_column(nullable=False)
    role = Column(String, default="admin")

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(unique=True, nullable=False)
    firstname: Mapped[str] = mapped_column(unique=True, nullable=False) 
    lastname: Mapped[str] = mapped_column(unique=True, nullable=False)
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(nullable=False)
    role: Mapped[UserRole] = mapped_column(String(30), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class TokenTable(Base):
    __tablename__ = "token"
    user_id : Mapped[int]
    access_token : Mapped[str] = mapped_column( primary_key=True)
    refresh_token: Mapped[str] = mapped_column(nullable=False)
    status: Mapped[bool] = mapped_column(default=True)
    created_date : Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Reaction(Base):
    __tablename__ = 'reactions'

    id : Mapped[int] = mapped_column(primary_key=True, index=True)
    reaction : Mapped[str] = mapped_column(index=True)

    
@event.listens_for(Teacher, "after_insert")
def create_user_record_for_teacher(mapper, connection, target):
    user = User(
        username=target.email,
        firstname=target.name,
        lastname=target.lastname,
        email=target.email,
        hashed_password=target.password,
        role="teacher"
    )
    connection.execute(User.__table__.insert(), user.__dict__)

@event.listens_for(Student, "after_insert")
def create_user_record_for_student(mapper, connection, target):
    user = User(
        username=target.email,
        firstname=target.name,
        lastname=target.lastname,
        email=target.email,
        hashed_password=target.password,
        role="student"
    )
    connection.execute(User.__table__.insert(), user.__dict__)