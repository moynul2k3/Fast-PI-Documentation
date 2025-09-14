# FastAPI + Tortoise ORM + MySQL — Production-ready starter

> Complete, well-structured FastAPI project using Tortoise ORM, MySQL, Docker, and Aerich for migrations. Contains auth (JWT), CRUD example for `Item`, logging, config via environment variables, and recommended production notes.

---

## File tree & explanation

```
fastapi-tortoise-mysql/
├── app/
│   ├── __init__.py              # Marks the `app` folder as a package
│   ├── main.py                  # FastAPI app entrypoint; includes routers and DB lifecycle
│   ├── config.py                # Centralized configuration (from .env via Pydantic)
│   ├── db.py                    # Tortoise ORM init/close + config dict for Aerich
│   ├── models.py                # Tortoise ORM models (User, Item)
│   ├── schemas.py               # Pydantic schemas (validation/serialization)
│   ├── crud.py                  # CRUD functions for User and Item
│   ├── deps.py                  # Dependencies (auth, current user)
│   ├── utils/
│   │   ├── security.py          # Password hashing, JWT creation/validation
│   │   └── logging_config.py    # Configures Python logging format and level
│   └── api/
│       ├── __init__.py          # Package marker for API
│       ├── v1/                  # Versioned API folder
│       │   ├── __init__.py
│       │   ├── auth.py          # Routes for register/login
│       │   └── items.py         # Routes for Item CRUD
├── migrations/                  # Aerich creates migration files here
├── tests/
│   ├── conftest.py              # Pytest fixtures (async client)
│   └── test_items.py            # Example test for item routes
├── docker-compose.yml           # Compose file (MySQL + app)
├── Dockerfile                   # Build instructions for app image
├── requirements.txt             # Python dependencies
├── .env.example                 # Example environment config
├── aerich.ini                   # Aerich migration tool config
├── README.md                    # Project documentation
└── .gitignore                   # Ignore unnecessary files in Git
```

---

## Why each file/folder exists

### **Core app files**
- **`main.py`**: Entry point. Creates FastAPI app, includes routers (`auth`, `items`), sets up DB on startup/shutdown.
- **`config.py`**: Loads environment variables (DB, JWT, etc.) using Pydantic `BaseSettings`. Central place for configuration.
- **`db.py`**: Holds `TORTOISE_ORM` dict for Tortoise + Aerich, defines `init_db`/`close_db` functions.
- **`models.py`**: Defines Tortoise ORM models (`User`, `Item`) that become MySQL tables.
- **`schemas.py`**: Pydantic models used for request/response validation.
- **`crud.py`**: Encapsulates database access logic (create user, auth, CRUD items).
- **`deps.py`**: Provides dependencies for routes (e.g., `get_current_user` from JWT token).

### **Utilities**
- **`utils/security.py`**: Handles password hashing with Passlib and JWT encode/decode with `python-jose`.
- **`utils/logging_config.py`**: Standard logging configuration (can be extended to file, Sentry, etc.).

### **API**
- **`api/v1/auth.py`**: Implements `/auth/register` and `/auth/token` endpoints for user management.
- **`api/v1/items.py`**: Implements `/items` endpoints for CRUD operations with permission checks.
- **`api/v1` folder**: Organizes routes under versioning (e.g., `/api/v1/...`).

### **Migrations**
- **`aerich.ini`**: Aerich config, points to `app.db.TORTOISE_ORM`.
- **`migrations/`**: Generated migration files live here (schema changes).

### **Tests**
- **`tests/conftest.py`**: Sets up reusable pytest fixtures (async client).
- **`tests/test_items.py`**: Example test to verify the `/items` endpoint.

### **Deployment & dependencies**
- **`Dockerfile`**: Defines container build (Python base, install deps, run app with Gunicorn/Uvicorn).
- **`docker-compose.yml`**: Runs app + MySQL locally, mounts volume for DB persistence.
- **`requirements.txt`**: Locked versions of dependencies.
- **`.env.example`**: Template of env vars needed to run app (DB, JWT, etc.).
- **`.gitignore`**: Prevents committing secrets, caches, build artifacts.

### **Docs & meta**
- **`README.md`**: Explains project setup, usage, production notes.

---

This way every file has a clear responsibility:
- **`app/`**: core business logic.
- **`api/`**: routes grouped by version.
- **`utils/`**: helper functions (security, logging).
- **`tests/`**: ensure code works.
- **Docker & env files**: deployment and configuration.

---

The rest of the document (already present) contains **actual file contents**, **setup steps**, and a **production checklist**.

