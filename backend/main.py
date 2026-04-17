import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager

from models.database import init_db
from auth.routes import router as auth_router
from auth.admin_routes import router as admin_router
from files.routes import router as files_router

limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # Create default admin if none exists
    from models.database import AsyncSessionLocal
    from models.models import User
    from auth.auth import hash_password
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        if not result.scalar_one_or_none():
            admin = User(
                username="admin",
                email="admin@securefms.local",
                hashed_password=hash_password("Admin@12345"),
                role="admin",
            )
            db.add(admin)
            await db.commit()
            print("✅ Default admin created: admin / Admin@12345")
    yield

app = FastAPI(
    title="Secure File Management System",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(files_router)

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "SecureFMS"}
