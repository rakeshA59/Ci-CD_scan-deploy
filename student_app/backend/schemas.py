"""Pydantic schemas for request validation and response serialization."""
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class StudentBase(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)
    email: str = Field(..., max_length=120)
    department: str = Field(..., min_length=1, max_length=80)
    year: int = Field(..., ge=1, le=6)


class StudentCreate(StudentBase):
    pass


class StudentUpdate(BaseModel):
    first_name: Optional[str] = Field(None, min_length=1, max_length=50)
    last_name: Optional[str] = Field(None, min_length=1, max_length=50)
    email: Optional[str] = Field(None, max_length=120)
    department: Optional[str] = Field(None, min_length=1, max_length=80)
    year: Optional[int] = Field(None, ge=1, le=6)


class StudentOut(StudentBase):
    model_config = ConfigDict(from_attributes=True)
    id: int


class CourseCreate(BaseModel):
    code: str = Field(..., min_length=2, max_length=20)
    title: str = Field(..., min_length=1, max_length=120)
    credits: int = Field(..., ge=1, le=10)


class CourseOut(CourseCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int


class EnrollmentCreate(BaseModel):
    student_id: int
    course_id: int
    score: Optional[float] = None


class EnrollmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    student_id: int
    course_id: int
    score: Optional[float]


class TranscriptLine(BaseModel):
    course_code: str
    course_title: str
    credits: int
    score: Optional[float]
    letter: Optional[str]


class Transcript(BaseModel):
    student: StudentOut
    courses: List[TranscriptLine]
    gpa: Optional[float]
    total_credits: int
    standing: str
