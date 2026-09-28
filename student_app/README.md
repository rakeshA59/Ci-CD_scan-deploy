# Student College Info App

A small full-stack Python app for testing code scanning, LLM unit-test generation,
test execution, packaging and containerization pipelines.

## Tech stack
| Layer     | Tech |
|-----------|------|
| Backend   | FastAPI 0.115, Uvicorn |
| ORM / DB  | SQLAlchemy 2.0, SQLite (`students.db`, auto-created + seeded) |
| Validation| Pydantic 2 |
| Frontend  | HTML + CSS + vanilla JavaScript (served by FastAPI at `/`) |
| Language  | Python 3.10+ |

## Project layout
```
student_app/
├── requirements.txt
├── backend/
│   ├── __init__.py
│   ├── main.py        # FastAPI app, routes, static frontend
│   ├── database.py    # engine, session, get_db dependency
│   ├── models.py      # Student, Course, Enrollment tables
│   ├── schemas.py     # Pydantic request/response models
│   ├── crud.py        # DB operations + seed data
│   └── services.py    # pure logic: grades, GPA, standing, validation
└── frontend/
    ├── index.html
    ├── app.js
    └── style.css
```
Intentionally **not** included: tests, Dockerfile, packaging config (pyproject/setup.py), CI.

## Run
```bash
cd student_app
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
uvicorn backend.main:app --reload
```
- UI: http://127.0.0.1:8000
- Swagger docs: http://127.0.0.1:8000/docs

Delete `students.db` to start fresh.

## API
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/students?q=&skip=&limit=` | List / search students |
| GET | `/api/students/{id}` | Get one student |
| POST | `/api/students` | Create student (409 on duplicate email) |
| PUT | `/api/students/{id}` | Partial update |
| DELETE | `/api/students/{id}` | Delete student |
| GET | `/api/students/{id}/transcript` | Courses, letter grades, GPA, standing |
| GET | `/api/courses` | List courses |
| POST | `/api/courses` | Create course |
| POST | `/api/enrollments` | Enroll a student (optional score 0–100) |
| POST | `/api/admin/reset` | Drop + reseed DB (needs `X-API-Key` header) |

## Good unit-test targets (`backend/services.py`)
- `score_to_letter(score)` — boundaries 59.9/60/70/80/90/100, raises `ValueError` outside 0–100
- `calculate_gpa([(score, credits), ...])` — credit-weighted, skips `None`, returns `None` if nothing graded
- `academic_standing(gpa)` — `None` / 3.5 / 2.0 thresholds
- `is_valid_email`, `normalize_name`, `parse_score`

---

## Planted issues (answer key for your scanner — don't show this to the LLM)
| # | File | Issue | Type |
|---|------|-------|------|
| 1 | `backend/database.py` | Hardcoded secret `ADMIN_API_KEY = "sk-admin-..."` | Security (secrets) |
| 2 | `backend/crud.py` → `search_students` | SQL built with f-string from user input → SQL injection | Security (injection) |
| 3 | `backend/services.py` → `parse_score` | Bare `except:` that silently returns `0.0` | Code quality / error handling |
| 4 | `backend/crud.py` → `delete_student` + `main.py` DELETE route | No existence check → deleting a missing ID returns **500** instead of 404 | Bug (a generated test should catch it) |
| 5 | `backend/schemas.py` (`EmailStr`), `backend/crud.py` (`json`), `backend/main.py` (`models`) | Unused imports | Lint |
| 6 | `backend/crud.py` → `seed` | Magic-number index tuples, long lines | Maintainability |
