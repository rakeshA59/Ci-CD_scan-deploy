"""Walk the repository and collect structural facts (no code interpretation)."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from cip.utils import iter_files, rel

KEY_FILES = [
    "requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "pyproject.toml", "setup.py",
    "setup.cfg", "Pipfile", "poetry.lock", "environment.yml", "pixi.toml", "Dockerfile",
    "docker-compose.yml", "docker-compose.yaml", "compose.yaml", ".env.example", ".env_example",
    "Makefile", "README.md", "pytest.ini", "tox.ini", "conftest.py", "alembic.ini", "manage.py",
    ".gitlab-ci.yml", "Jenkinsfile", "Procfile", ".dockerignore",
]

LANG_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript", ".java": "Java", ".go": "Go", ".rb": "Ruby", ".cs": "C#",
    ".php": "PHP", ".rs": "Rust", ".kt": "Kotlin", ".sql": "SQL", ".sh": "Shell",
    ".html": "HTML", ".css": "CSS", ".yml": "YAML", ".yaml": "YAML", ".json": "JSON",
}


def build_tree(root: Path, max_depth: int = 3, max_entries: int = 200) -> str:
    lines, count = [root.name + "/"], 0

    def walk(d: Path, depth: int, prefix: str):
        nonlocal count
        if depth > max_depth or count > max_entries:
            return
        from cip.utils import IGNORED_DIRS
        try:
            entries = sorted(d.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except OSError:
            return
        entries = [e for e in entries if e.name not in IGNORED_DIRS and not e.name.endswith(".egg-info")]
        for i, e in enumerate(entries):
            count += 1
            if count > max_entries:
                lines.append(prefix + "└── …")
                return
            last = i == len(entries) - 1
            lines.append(f"{prefix}{'└── ' if last else '├── '}{e.name}{'/' if e.is_dir() else ''}")
            if e.is_dir():
                walk(e, depth + 1, prefix + ("    " if last else "│   "))

    walk(root, 1, "")
    return "\n".join(lines)


def scan_repository(root: Path) -> dict:
    files = list(iter_files(root))
    ext_counter = Counter(p.suffix.lower() for p in files)
    lang_counter: Counter = Counter()
    loc_by_lang: Counter = Counter()
    for p in files:
        lang = LANG_BY_EXT.get(p.suffix.lower())
        if lang:
            lang_counter[lang] += 1
            if lang in ("Python", "JavaScript", "TypeScript", "Java", "Go"):
                try:
                    loc_by_lang[lang] += sum(1 for _ in p.open(encoding="utf-8", errors="ignore"))
                except OSError:
                    pass

    present_key_files = sorted({rel(p, root) for p in files if p.name in KEY_FILES})
    test_files = [rel(p, root) for p in files if p.suffix == ".py" and
                  (p.name.startswith("test_") or p.name.endswith("_test.py") or "tests" in p.parts)]
    top_dirs = sorted(d.name for d in root.iterdir() if d.is_dir() and not d.name.startswith("."))

    return {
        "root": str(root),
        "name": root.name,
        "total_files": len(files),
        "files_by_extension": dict(ext_counter.most_common(15)),
        "files_by_language": dict(lang_counter.most_common()),
        "lines_of_code": dict(loc_by_lang),
        "key_files": present_key_files,
        "top_level_dirs": top_dirs,
        "test_files": test_files,
        "has_tests": bool(test_files),
        "has_dockerfile": any(Path(k).name == "Dockerfile" for k in present_key_files),
        "tree": build_tree(root),
    }
