"""FastAPI application entry point.

Run from the project root:
    uvicorn backend.main:app --reload
Then open http://127.0.0.1:8000
"""
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from . import crud, models, schemas, services
from .database import ADMIN_API_KEY, Base, SessionLocal, engine, get_db

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        crud.seed(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Student College Info API", version="1.0.0", lifespan=lifespan)


# ---------- Health ----------

@app.get("/api/health")
def health():
    return {"status": "ok"}


# ---------- Students ----------

@app.get("/api/students", response_model=List[schemas.StudentOut])
def list_students(q: Optional[str] = None, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    if q:
        return crud.search_students(db, q)
    return crud.get_students(db, skip=skip, limit=limit)


@app.get("/api/students/{student_id}", response_model=schemas.StudentOut)
def read_student(student_id: int, db: Session = Depends(get_db)):
    student = crud.get_student(db, student_id)
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    return student


@app.post("/api/students", response_model=schemas.StudentOut, status_code=status.HTTP_201_CREATED)
def create_student(payload: schemas.StudentCreate, db: Session = Depends(get_db)):
    if not services.is_valid_email(payload.email):
        raise HTTPException(status_code=422, detail="Invalid email address")
    if crud.get_student_by_email(db, payload.email.lower().strip()):
        raise HTTPException(status_code=409, detail="Email already registered")
    return crud.create_student(db, payload)


@app.put("/api/students/{student_id}", response_model=schemas.StudentOut)
def update_student(student_id: int, payload: schemas.StudentUpdate, db: Session = Depends(get_db)):
    student = crud.get_student(db, student_id)
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    if payload.email is not None and not services.is_valid_email(payload.email):
        raise HTTPException(status_code=422, detail="Invalid email address")
    return crud.update_student(db, student, payload)


@app.delete("/api/students/{student_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_student(student_id: int, db: Session = Depends(get_db)):
    crud.delete_student(db, student_id)


@app.get("/api/students/{student_id}/transcript", response_model=schemas.Transcript)
def student_transcript(student_id: int, db: Session = Depends(get_db)):
    student = crud.get_student(db, student_id)
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    return crud.build_transcript(student)


# ---------- Courses & enrollments ----------

@app.get("/api/courses", response_model=List[schemas.CourseOut])
def list_courses(db: Session = Depends(get_db)):
    return crud.get_courses(db)


@app.post("/api/courses", response_model=schemas.CourseOut, status_code=status.HTTP_201_CREATED)
def create_course(payload: schemas.CourseCreate, db: Session = Depends(get_db)):
    return crud.create_course(db, payload)


@app.post("/api/enrollments", response_model=schemas.EnrollmentOut, status_code=status.HTTP_201_CREATED)
def enroll(payload: schemas.EnrollmentCreate, db: Session = Depends(get_db)):
    if not crud.get_student(db, payload.student_id):
        raise HTTPException(status_code=404, detail="Student not found")
    if not crud.get_course(db, payload.course_id):
        raise HTTPException(status_code=404, detail="Course not found")
    if payload.score is not None and not 0 <= payload.score <= 100:
        raise HTTPException(status_code=422, detail="Score must be between 0 and 100")
    return crud.create_enrollment(db, payload)


# ---------- Admin ----------

@app.post("/api/admin/reset")
def reset_database(x_api_key: str = Header(...), db: Session = Depends(get_db)):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    crud.seed(db)
    return {"status": "reset"}


# ---------- Frontend ----------

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(FRONTEND_DIR / "index.html")
