"""Engines: async for the API, sync for Celery workers (same models, same URL)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from vibeguard.config import get_settings


def async_url(url: str) -> str:
    return (
        url.replace("sqlite://", "sqlite+aiosqlite://", 1) if url.startswith("sqlite://") else url
    )


def sync_url(url: str) -> str:
    return url.replace("sqlite+aiosqlite://", "sqlite://", 1)


@lru_cache
def async_engine(url: str | None = None) -> AsyncEngine:
    return create_async_engine(async_url(url or get_settings().database_url), pool_pre_ping=True)


@lru_cache
def sync_engine(url: str | None = None) -> Engine:
    return create_engine(sync_url(url or get_settings().database_url), pool_pre_ping=True)


def async_session_factory(url: str | None = None) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(async_engine(url), expire_on_commit=False)


def sync_session_factory(url: str | None = None) -> sessionmaker[Session]:
    return sessionmaker(sync_engine(url), expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with async_session_factory()() as session:
        yield session
