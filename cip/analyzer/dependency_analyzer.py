"""Parse dependency manifests and classify packages into technology categories."""
from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

from cip.utils import iter_files, read_text, rel

# package (normalised) -> (category, display name)
KNOWN_PACKAGES: dict[str, tuple[str, str]] = {
    # web frameworks
    "fastapi": ("framework", "FastAPI"), "flask": ("framework", "Flask"),
    "django": ("framework", "Django"), "starlette": ("framework", "Starlette"),
    "aiohttp": ("framework", "aiohttp"), "tornado": ("framework", "Tornado"),
    "sanic": ("framework", "Sanic"), "streamlit": ("framework", "Streamlit"),
    "djangorestframework": ("framework", "Django REST Framework"), "gradio": ("framework", "Gradio"),
    # servers
    "uvicorn": ("server", "Uvicorn"), "gunicorn": ("server", "Gunicorn"), "hypercorn": ("server", "Hypercorn"),
    # databases
    "pymongo": ("database", "MongoDB"), "motor": ("database", "MongoDB (async)"),
    "beanie": ("database", "MongoDB (Beanie ODM)"), "mongoengine": ("database", "MongoDB"),
    "sqlalchemy": ("database", "SQLAlchemy (SQL)"), "psycopg2": ("database", "PostgreSQL"),
    "psycopg2-binary": ("database", "PostgreSQL"), "psycopg": ("database", "PostgreSQL"),
    "asyncpg": ("database", "PostgreSQL"), "pymysql": ("database", "MySQL"),
    "mysql-connector-python": ("database", "MySQL"), "redis": ("database", "Redis"),
    "elasticsearch": ("database", "Elasticsearch"), "cassandra-driver": ("database", "Cassandra"),
    "chromadb": ("vector_db", "ChromaDB"), "pinecone-client": ("vector_db", "Pinecone"),
    "pinecone": ("vector_db", "Pinecone"), "faiss-cpu": ("vector_db", "FAISS"),
    "qdrant-client": ("vector_db", "Qdrant"), "weaviate-client": ("vector_db", "Weaviate"),
    "pgvector": ("vector_db", "pgvector"), "alembic": ("database", "Alembic migrations"),
    # auth / security
    "pyjwt": ("auth", "JWT (PyJWT)"), "python-jose": ("auth", "JWT (python-jose)"),
    "passlib": ("auth", "Password hashing (passlib)"), "bcrypt": ("auth", "bcrypt"),
    "authlib": ("auth", "OAuth (Authlib)"), "msal": ("auth", "Azure AD (MSAL)"),
    "fastapi-users": ("auth", "fastapi-users"), "cryptography": ("auth", "cryptography"),
    # AI / LLM
    "openai": ("ai", "OpenAI"), "anthropic": ("ai", "Anthropic"), "langchain": ("ai", "LangChain"),
    "langchain-core": ("ai", "LangChain"), "langchain-openai": ("ai", "LangChain OpenAI"),
    "langgraph": ("ai", "LangGraph"), "llama-index": ("ai", "LlamaIndex"),
    "transformers": ("ai", "HuggingFace Transformers"), "google-generativeai": ("ai", "Google Gemini"),
    "google-genai": ("ai", "Google Gemini"), "langfuse": ("ai", "Langfuse"),
    "tiktoken": ("ai", "tiktoken"), "sentence-transformers": ("ai", "Sentence Transformers"),
    "torch": ("ml", "PyTorch"), "tensorflow": ("ml", "TensorFlow"), "scikit-learn": ("ml", "scikit-learn"),
    # data / validation
    "pydantic": ("validation", "Pydantic"), "marshmallow": ("validation", "Marshmallow"),
    "pandas": ("data", "pandas"), "numpy": ("data", "NumPy"),
    # messaging / tasks
    "celery": ("messaging", "Celery"), "kafka-python": ("messaging", "Kafka"),
    "confluent-kafka": ("messaging", "Kafka"), "pika": ("messaging", "RabbitMQ"),
    "azure-servicebus": ("messaging", "Azure Service Bus"),
    # cloud
    "boto3": ("cloud", "AWS (boto3)"), "azure-storage-blob": ("cloud", "Azure Blob Storage"),
    "azure-identity": ("cloud", "Azure Identity"), "azure-keyvault-secrets": ("cloud", "Azure Key Vault"),
    "google-cloud-storage": ("cloud", "GCP Storage"),
    # http clients
    "requests": ("http_client", "requests"), "httpx": ("http_client", "httpx"),
    # testing
    "pytest": ("testing", "pytest"), "pytest-asyncio": ("testing", "pytest-asyncio"),
    "pytest-cov": ("testing", "pytest-cov"), "unittest2": ("testing", "unittest"),
    "mongomock": ("testing", "mongomock"), "hypothesis": ("testing", "Hypothesis"),
    # templating / docs
    "jinja2": ("templating", "Jinja2"), "python-docx": ("documents", "python-docx"),
}

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(?:(==|>=|<=|~=|!=|>|<)\s*([^;#\s]+))?")


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.split("[")[0]).lower()


def _parse_requirements(path: Path) -> list[dict]:
    deps = []
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = _REQ_LINE.match(line)
        if m:
            deps.append({"name": normalise(m.group(1)), "spec": (m.group(2) or "") + (m.group(3) or ""),
                         "pinned": m.group(2) == "==", "source": path.name})
    return deps


def _parse_pyproject(path: Path) -> tuple[list[dict], dict]:
    if not tomllib:
        return [], {}
    try:
        data = tomllib.loads(read_text(path))
    except Exception:
        return [], {}
    raw: list[str] = list(data.get("project", {}).get("dependencies", []) or [])
    for grp in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
        raw += grp
    poetry = data.get("tool", {}).get("poetry", {})
    for name, spec in (poetry.get("dependencies", {}) or {}).items():
        if name.lower() != "python":
            raw.append(f"{name}{spec if isinstance(spec, str) and spec[0:1] in '<>=~!' else ''}")
    deps = []
    for r in raw:
        m = _REQ_LINE.match(r)
        if m:
            deps.append({"name": normalise(m.group(1)), "spec": (m.group(2) or "") + (m.group(3) or ""),
                         "pinned": m.group(2) == "==", "source": "pyproject.toml"})
    meta = {
        "project_name": data.get("project", {}).get("name") or poetry.get("name"),
        "requires_python": data.get("project", {}).get("requires-python")
        or (poetry.get("dependencies", {}) or {}).get("python"),
        "build_backend": data.get("build-system", {}).get("build-backend"),
    }
    return deps, meta


def analyze_dependencies(root: Path) -> dict:
    deps: list[dict] = []
    meta: dict = {}
    manifests = []
    for p in iter_files(root, {".txt", ".toml", ".py", ".yml", ""}):
        name = p.name.lower()
        if name.startswith("requirements") and name.endswith(".txt"):
            deps += _parse_requirements(p)
            manifests.append(rel(p, root))
        elif name == "pyproject.toml":
            d, meta = _parse_pyproject(p)
            deps += d
            manifests.append(rel(p, root))
        elif name in ("setup.py", "pipfile", "environment.yml", "pixi.toml"):
            manifests.append(rel(p, root))

    # de-duplicate by name, keep first
    seen, unique = set(), []
    for d in deps:
        if d["name"] not in seen:
            seen.add(d["name"])
            unique.append(d)

    categories: dict[str, list[str]] = {}
    for d in unique:
        known = KNOWN_PACKAGES.get(d["name"])
        if known:
            cat, label = known
            if label not in categories.setdefault(cat, []):
                categories[cat].append(label)

    python_version = meta.get("requires_python")
    for f in (".python-version", "runtime.txt"):
        fp = root / f
        if fp.exists():
            python_version = read_text(fp).strip().replace("python-", "")

    return {
        "manifests": manifests,
        "dependencies": unique,
        "dependency_count": len(unique),
        "unpinned": [d["name"] for d in unique if not d["pinned"]],
        "categories": categories,
        "python_version": python_version,
        "project_meta": meta,
    }
