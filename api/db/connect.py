from typing import AsyncIterable
from sqlalchemy.ext.asyncio.engine import AsyncEngine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from api.models.user import User
from api.models.chat import Chat
from api.models.message import Message
from api.config import Config

engine: AsyncEngine = create_async_engine(Config.POSTGRES_URL, echo=True)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


async def get_session() -> AsyncIterable[AsyncSession]:
    async_session = AsyncSession(
        bind=engine,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
        future=True,
    )
    async with async_session as session:
        yield session
