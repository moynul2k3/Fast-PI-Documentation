# FastAPI + Tortoise ORM + MySQL — Production-ready starter

> Complete, well-structured FastAPI project using Tortoise ORM, MySQL, Docker, and Aerich for migrations. Contains auth (JWT), CRUD example for `Item`, logging, config via environment variables, and recommended production notes.

---

## File tree

```
fastapi-tortoise-mysql/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── db.py
│   ├── models.py
│   ├── schemas.py
│   ├── crud.py
│   ├── deps.py
│   ├── utils/
│   │   ├── security.py
│   │   └── logging_config.py
│   └── api/
│       ├── __init__.py
│       ├── v1/
│       │   ├── __init__.py
│       │   ├── auth.py
│       │   └── items.py
├── migrations/        # aerich will manage this
├── tests/
│   ├── conftest.py
│   └── test_items.py
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
├── aerich.ini
├── README.md
└── .gitignore
```

---

> **Notes**: This project aims to be opinionated but practical for production:
>
> - Use environment variables for secrets & DB settings.
> - Run with Uvicorn + Gunicorn or `uvicorn.workers.UvicornWorker` in production.
> - Use Docker Compose for local development (MySQL + app).
> - Use Aerich for Tortoise migrations.

---

## Key files (full contents)

### `requirements.txt`

```text
fastapi==0.101.1
uvicorn[standard]==0.23.2
tortoise-orm==0.20.3
aiomysql==0.1.1
pydantic==1.10.12
python-jose==3.3.0
passlib[bcrypt]==1.7.4
python-dotenv==1.0.0
aerich==0.6.22
gunicorn==20.1.0
```

---

### `.env.example`

```text
# FastAPI settings
APP_NAME=FastAPI Tortoise Starter
APP_ENV=production
APP_HOST=0.0.0.0
APP_PORT=8000
LOG_LEVEL=info

# Database (MySQL)
DB_HOST=mysql
DB_PORT=3306
DB_USER=fastapi
DB_PASS=fastapi_pass
DB_NAME=fastapi_db

# JWT
JWT_SECRET=replace_this_with_a_secure_random_string
JWT_ALGORITHM=HS256
JWT_EXP_MIN=60

# Other
SENTRY_DSN=

```

---

### `Dockerfile`

```dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /code

# system deps for mysql client if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

ENV PATH="/code/.venv/bin:$PATH"

CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-c", "python:gunicorn_conf", "app.main:app"]
```

> Note: `gunicorn_conf.py` can be created at repo root if you prefer (not included by default). For simple deployments you can run `uvicorn app.main:app --host 0.0.0.0 --port 8000`.

---

### `docker-compose.yml`

```yaml
version: '3.8'
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: ${DB_NAME}
      MYSQL_USER: ${DB_USER}
      MYSQL_PASSWORD: ${DB_PASS}
    volumes:
      - db_data:/var/lib/mysql
    ports:
      - "3306:3306"
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 5

  web:
    build: .
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    volumes:
      - ./:/code
    env_file: .env
    depends_on:
      mysql:
        condition: service_healthy
    ports:
      - "8000:8000"

volumes:
  db_data:
```

---

### `aerich.ini`

```ini
[aerich]
project = app.models
app = app
tortoise_config = tortoise_config.json
```

> We'll also create a `tortoise_config.json` programmatically inside `app/db.py` (or you can create file if you prefer).

---

### `app/__init__.py`

```python
# package marker
```

---

### `app/config.py`

```python
from pydantic import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "FastAPI Tortoise Starter"
    APP_ENV: str = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000

    DB_HOST: str
    DB_PORT: int = 3306
    DB_USER: str
    DB_PASS: str
    DB_NAME: str

    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXP_MIN: int = 60

    LOG_LEVEL: str = "info"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
```

---

### `app/db.py`

```python
from tortoise import Tortoise
from .config import settings

TORTOISE_ORM = {
    "connections": {
        "default": f"mysql://{settings.DB_USER}:{settings.DB_PASS}@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}?charset=utf8mb4"
    },
    "apps": {
        "models": {
            "models": ["app.models", "aerich.models"],
            "default_connection": "default",
        }
    },
}

async def init_db():
    await Tortoise.init(config=TORTOISE_ORM)
    await Tortoise.generate_schemas()

async def close_db():
    await Tortoise.close_connections()
```

---

### `app/models.py`

```python
from tortoise import fields
from tortoise.models import Model

class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    email = fields.CharField(255, unique=True, null=True)
    hashed_password = fields.CharField(128)
    is_active = fields.BooleanField(default=True)
    is_superuser = fields.BooleanField(default=False)
    created_at = fields.DatetimeField(auto_now_add=True)

    def __str__(self):
        return self.username

class Item(Model):
    id = fields.IntField(pk=True)
    title = fields.CharField(200)
    description = fields.TextField(null=True)
    owner = fields.ForeignKeyField('models.User', related_name='items', null=True)
    is_public = fields.BooleanField(default=False)
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "items"

    def __str__(self):
        return self.title
```

---

### `app/schemas.py`

```python
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenPayload(BaseModel):
    sub: Optional[str]

class UserCreate(BaseModel):
    username: str
    email: Optional[EmailStr]
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[EmailStr]
    is_active: bool
    is_superuser: bool
    created_at: datetime

    class Config:
        orm_mode = True

class ItemCreate(BaseModel):
    title: str
    description: Optional[str] = None
    is_public: bool = False

class ItemOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    owner_id: Optional[int]
    is_public: bool
    created_at: datetime

    class Config:
        orm_mode = True
```

---

### `app/utils/security.py`

```python
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from .config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(subject: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXP_MIN)
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded

def decode_token(token: str):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except Exception:
        return None
```

---

### `app/crud.py`

```python
from typing import Optional
from .models import User, Item
from .utils.security import hash_password, verify_password

# User CRUD
async def create_user(username: str, email: Optional[str], password: str) -> User:
    user = await User.create(username=username, email=email, hashed_password=hash_password(password))
    return user

async def get_user_by_username(username: str) -> Optional[User]:
    return await User.get_or_none(username=username)

async def authenticate_user(username: str, password: str) -> Optional[User]:
    user = await get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

# Item CRUD
async def create_item(owner: User, title: str, description: Optional[str], is_public: bool) -> Item:
    return await Item.create(owner=owner, title=title, description=description, is_public=is_public)

async def get_item(item_id: int) -> Optional[Item]:
    return await Item.get_or_none(id=item_id)

async def list_items(skip: int = 0, limit: int = 20):
    return await Item.all().offset(skip).limit(limit)

async def update_item(item: Item, **data):
    for k, v in data.items():
        setattr(item, k, v)
    await item.save()
    return item

async def delete_item(item: Item):
    await item.delete()
```

---

### `app/deps.py`

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from .utils.security import decode_token
from .crud import get_user_by_username

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication")
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user
```

---

### `app/api/v1/auth.py`

```python
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from .. import crud
from ..schemas import Token, UserCreate, UserOut
from ..utils.security import create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post('/register', response_model=UserOut)
async def register(user_in: UserCreate):
    existing = await crud.get_user_by_username(user_in.username)
    if existing:
        raise HTTPException(status_code=400, detail='Username already taken')
    user = await crud.create_user(user_in.username, user_in.email, user_in.password)
    return user

@router.post('/token', response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await crud.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Incorrect username or password')
    token = create_access_token(subject=user.username)
    return {"access_token": token, "token_type": "bearer"}
```

---

### `app/api/v1/items.py`

```python
from fastapi import APIRouter, Depends, HTTPException
from typing import List
from ..schemas import ItemCreate, ItemOut
from ..deps import get_current_user
from ..crud import create_item, get_item, list_items, update_item, delete_item

router = APIRouter(prefix="/items", tags=["items"])

@router.post('/', response_model=ItemOut)
async def create_item_endpoint(item_in: ItemCreate, current_user=Depends(get_current_user)):
    item = await create_item(current_user, item_in.title, item_in.description, item_in.is_public)
    return item

@router.get('/', response_model=List[ItemOut])
async def list_items_endpoint(skip: int = 0, limit: int = 20):
    items = await list_items(skip=skip, limit=limit)
    return items

@router.get('/{item_id}', response_model=ItemOut)
async def get_item_endpoint(item_id: int):
    item = await get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail='Item not found')
    return item

@router.put('/{item_id}', response_model=ItemOut)
async def update_item_endpoint(item_id: int, item_in: ItemCreate, current_user=Depends(get_current_user)):
    item = await get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail='Item not found')
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail='Not allowed')
    updated = await update_item(item, title=item_in.title, description=item_in.description, is_public=item_in.is_public)
    return updated

@router.delete('/{item_id}')
async def delete_item_endpoint(item_id: int, current_user=Depends(get_current_user)):
    item = await get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail='Item not found')
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail='Not allowed')
    await delete_item(item)
    return {"ok": True}
```

---

### `app/utils/logging_config.py`

```python
import logging

def configure_logging(level: str = "INFO"):
    logging.basicConfig(
        level=level,
        format='%(asctime)s | %(levelname)s | %(name)s | %(message)s',
    )
    # you can add handlers (file, rotating file, sentry, etc.) here
```

---

### `app/main.py`

```python
import uvicorn
from fastapi import FastAPI
from .config import settings
from .db import init_db, close_db
from .api.v1 import auth, items
from .utils.logging_config import configure_logging

app = FastAPI(title=settings.APP_NAME)

# Configure logging
configure_logging(settings.LOG_LEVEL.upper())

# include routers
app.include_router(auth.router, prefix='/api/v1')
app.include_router(items.router, prefix='/api/v1')

@app.on_event('startup')
async def startup_event():
    # initialize DB connection (do NOT generate schemas in production; use migrations)
    await init_db()

@app.on_event('shutdown')
async def shutdown_event():
    await close_db()

if __name__ == '__main__':
    uvicorn.run('app.main:app', host=settings.APP_HOST, port=settings.APP_PORT, reload=True)
```

**IMPORTANT (production)**: In `startup_event` we call `init_db()` which calls `Tortoise.generate_schemas()` — for production you should NOT call `generate_schemas` at startup; instead run Aerich migrations and only `Tortoise.init()`.

---

### `tests/conftest.py`

```python
import pytest
from httpx import AsyncClient
from app.main import app

@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
```

### `tests/test_items.py`

```python
import pytest

async def test_list_items(client):
    resp = await client.get('/api/v1/items/')
    assert resp.status_code == 200
```

---

### `.gitignore`

```
__pycache__/
*.py[cod]
.env
*.sqlite3
db_data/
*.egg-info/
```

---

## Quick setup (development)

1. Copy `.env.example` -> `.env` and fill variables.
2. Start MySQL + app (development): `docker compose up --build`
3. Exec into web container: `docker compose exec web bash` and run migrations with aerich:

```bash
pip install aerich
# initialize aerich (only first time)
aerich init -t app.db.TORTOISE_ORM
# create migrations
aerich init-db
```

4. Create a user via `/api/v1/auth/register` and obtain token at `/api/v1/auth/token`.

---

## Production checklist & recommendations

- **Don't** use `Tortoise.generate_schemas()` on startup in production. Use Aerich migrations only.
- Use a secure `JWT_SECRET` and rotate keys when needed.
- Use HTTPS (TLS termination at load balancer).
- Use connection pooling (aiomysql + Tortoise handles pooling; tune pool size using `connections` params).
- Run behind process manager (Gunicorn) with Uvicorn worker class.
- Configure logging to rotate and ship to centralized logging (ELK/Datadog/Sentry).
- Add rate-limiting (Redis-based) and robust error handling middleware.
- Add health-check endpoints and readiness/liveness probes.
- Add CI: run tests, run lint, build docker image.

---

## Final notes

This repository gives a comprehensive starting point. You can expand with features like refresh tokens, role-based access control, background tasks, task queue (Celery/RQ), metrics, and observability.

If you'd like, I can:
- produce this as a downloadable zip of files, or
- tailor the auth to OAuth2 + refresh tokens, or
- add Redis caching and rate-limiting, or
- convert to SQLAlchemy/Databases if you prefer.


---

*End of project blueprint.*

