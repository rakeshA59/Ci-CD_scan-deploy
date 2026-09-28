"""SQLAlchemy ORM models."""
from sqlalchemy import Column, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .database import Base


class Student(Base):
    __tablename__ = "students"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    email = Column(String(120), unique=True, nullable=False, index=True)
    department = Column(String(80), nullable=False)
    year = Column(Integer, nullable=False)

    enrollments = relationship(
        "Enrollment", back_populates="student", cascade="all, delete-orphan"
    )


class Course(Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(20), unique=True, nullable=False)
    title = Column(String(120), nullable=False)
    credits = Column(Integer, nullable=False)

    enrollments = relationship("Enrollment", back_populates="course")


class Enrollment(Base):
    __tablename__ = "enrollments"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("students.id"), nullable=False)
    course_id = Column(Integer, ForeignKey("courses.id"), nullable=False)
    score = Column(Float, nullable=True)  # 0-100, null until graded

    student = relationship("Student", back_populates="enrollments")
    course = relationship("Course", back_populates="enrollments")
