from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from models.models import Base
import os

DB_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./secure_fms.db")

engine = create_async_engine(DB_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
