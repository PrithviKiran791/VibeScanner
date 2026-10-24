"""The `users` row behind a verified Principal: created on first sign-in, kept in sync after."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vibeguard.api.auth import CurrentUser, Principal
from vibeguard.db.models import User
from vibeguard.db.session import get_session


async def upsert_account(session: AsyncSession, principal: Principal) -> User:
    profile = {
        "email": principal.email,
        "name": principal.name,
        "avatar_url": principal.picture,
        "github_id": principal.github_id,
    }
    user = await session.scalar(select(User).where(User.firebase_uid == principal.uid))
    if user is None:
        user = User(firebase_uid=principal.uid, **profile)
        session.add(user)
        try:
            await session.commit()
        except IntegrityError:
            # Two first requests raced; the other one created the row
            await session.rollback()
            user = await session.scalar(select(User).where(User.firebase_uid == principal.uid))
            assert user is not None
        return user

    changed = {k: v for k, v in profile.items() if getattr(user, k) != v}
    if changed:
        for key, value in changed.items():
            setattr(user, key, value)
        await session.commit()
    return user


async def current_account(
    principal: CurrentUser, session: Annotated[AsyncSession, Depends(get_session)]
) -> User:
    return await upsert_account(session, principal)


CurrentAccount = Annotated[User, Depends(current_account)]
