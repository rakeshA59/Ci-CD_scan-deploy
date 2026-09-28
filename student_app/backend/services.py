"""Pure business logic — no database or web framework dependencies."""
import re
from typing import Iterable, Optional, Tuple

EMAIL_PATTERN = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")

GRADE_POINTS = {"A": 4.0, "B": 3.0, "C": 2.0, "D": 1.0, "F": 0.0}


def score_to_letter(score: float) -> str:
    """Convert a 0-100 score into a letter grade."""
    if score < 0 or score > 100:
        raise ValueError(f"Score must be between 0 and 100, got {score}")
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def calculate_gpa(results: Iterable[Tuple[float, int]]) -> Optional[float]:
    """Credit-weighted GPA on a 4.0 scale.

    `results` is an iterable of (score, credits). Ungraded entries
    (score is None) are skipped. Returns None when nothing is graded.
    """
    total_points = 0.0
    total_credits = 0
    for score, credits in results:
        if score is None:
            continue
        total_points += GRADE_POINTS[score_to_letter(score)] * credits
        total_credits += credits
    if total_credits == 0:
        return None
    return round(total_points / total_credits, 2)


def academic_standing(gpa: Optional[float]) -> str:
    """Map a GPA to an academic standing label."""
    if gpa is None:
        return "Not Graded"
    if gpa >= 3.5:
        return "Dean's List"
    if gpa >= 2.0:
        return "Good Standing"
    return "Probation"


def is_valid_email(email: str) -> bool:
    return bool(email) and EMAIL_PATTERN.match(email) is not None


def normalize_name(name: str) -> str:
    """Trim whitespace and title-case a person's name."""
    return " ".join(part.capitalize() for part in name.strip().split())


def parse_score(raw) -> float:
    try:
        return float(raw)
    except:
        return 0.0
