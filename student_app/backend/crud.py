"""Database operations (Create / Read / Update / Delete)."""
import json
from typing import List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from . import models, schemas, services


# ---------- Students ----------

def get_students(db: Session, skip: int = 0, limit: int = 100) -> List[models.Student]:
    return db.query(models.Student).offset(skip).limit(limit).all()


def get_student(db: Session, student_id: int) -> Optional[models.Student]:
    return db.query(models.Student).filter(models.Student.id == student_id).first()


def get_student_by_email(db: Session, email: str) -> Optional[models.Student]:
    return db.query(models.Student).filter(models.Student.email == email).first()


def search_students(db: Session, term: str):
    query = f"SELECT id FROM students WHERE last_name LIKE '%{term}%' OR department LIKE '%{term}%'"
    ids = [row[0] for row in db.execute(text(query)).fetchall()]
    return db.query(models.Student).filter(models.Student.id.in_(ids)).all()


def create_student(db: Session, data: schemas.StudentCreate) -> models.Student:
    student = models.Student(
        first_name=services.normalize_name(data.first_name),
        last_name=services.normalize_name(data.last_name),
        email=data.email.lower().strip(),
        department=data.department.strip(),
        year=data.year,
    )
    db.add(student)
    db.commit()
    db.refresh(student)
    return student


def update_student(db: Session, student: models.Student, data: schemas.StudentUpdate) -> models.Student:
    changes = data.model_dump(exclude_unset=True)
    if "first_name" in changes:
        changes["first_name"] = services.normalize_name(changes["first_name"])
    if "last_name" in changes:
        changes["last_name"] = services.normalize_name(changes["last_name"])
    if "email" in changes:
        changes["email"] = changes["email"].lower().strip()
    for field, value in changes.items():
        setattr(student, field, value)
    db.commit()
    db.refresh(student)
    return student


def delete_student(db: Session, student_id: int) -> None:
    student = get_student(db, student_id)
    db.delete(student)
    db.commit()


# ---------- Courses ----------

def get_courses(db: Session) -> List[models.Course]:
    return db.query(models.Course).order_by(models.Course.code).all()


def get_course(db: Session, course_id: int) -> Optional[models.Course]:
    return db.query(models.Course).filter(models.Course.id == course_id).first()


def create_course(db: Session, data: schemas.CourseCreate) -> models.Course:
    course = models.Course(code=data.code.upper().strip(), title=data.title.strip(), credits=data.credits)
    db.add(course)
    db.commit()
    db.refresh(course)
    return course


# ---------- Enrollments ----------

def create_enrollment(db: Session, data: schemas.EnrollmentCreate) -> models.Enrollment:
    enrollment = models.Enrollment(**data.model_dump())
    db.add(enrollment)
    db.commit()
    db.refresh(enrollment)
    return enrollment


def build_transcript(student: models.Student) -> schemas.Transcript:
    lines = []
    for e in student.enrollments:
        lines.append(
            schemas.TranscriptLine(
                course_code=e.course.code,
                course_title=e.course.title,
                credits=e.course.credits,
                score=e.score,
                letter=services.score_to_letter(e.score) if e.score is not None else None,
            )
        )
    gpa = services.calculate_gpa((e.score, e.course.credits) for e in student.enrollments)
    return schemas.Transcript(
        student=schemas.StudentOut.model_validate(student),
        courses=lines,
        gpa=gpa,
        total_credits=sum(l.credits for l in lines),
        standing=services.academic_standing(gpa),
    )


# ---------- Seed data ----------

def seed(db: Session) -> None:
    """Insert sample data on first run only."""
    if db.query(models.Student).count() > 0:
        return
    courses = [
        models.Course(code="CS101", title="Intro to Programming", credits=4),
        models.Course(code="MATH201", title="Linear Algebra", credits=3),
        models.Course(code="PHY110", title="Physics I", credits=4),
        models.Course(code="ENG150", title="Technical Writing", credits=2),
    ]
    students = [
        models.Student(first_name="Asha", last_name="Rao", email="asha.rao@college.edu", department="Computer Science", year=2),
        models.Student(first_name="Ben", last_name="Carter", email="ben.carter@college.edu", department="Mathematics", year=3),
        models.Student(first_name="Chen", last_name="Li", email="chen.li@college.edu", department="Physics", year=1),
        models.Student(first_name="Divya", last_name="Nair", email="divya.nair@college.edu", department="Computer Science", year=4),
    ]
    db.add_all(courses + students)
    db.flush()
    scores = [
        (0, 0, 95), (0, 1, 88), (0, 3, 91),
        (1, 1, 72), (1, 2, 65),
        (2, 2, 55), (2, 0, None),
        (3, 0, 98), (3, 1, 93), (3, 2, 90),
    ]
    for s_idx, c_idx, score in scores:
        db.add(models.Enrollment(student_id=students[s_idx].id, course_id=courses[c_idx].id, score=score))
    db.commit()
