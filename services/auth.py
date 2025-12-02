"""Authentication helper utilities used by routes."""
from __future__ import annotations

from functools import wraps
from typing import Optional

from flask import flash, g, redirect, request, session, url_for

from models import db, User


def login_user(user: User) -> None:
    session['user_id'] = user.id
    session['is_admin'] = bool(user.is_admin)


def logout_user() -> None:
    session.pop('user_id', None)
    session.pop('is_admin', None)


def get_current_user() -> Optional[User]:
    if hasattr(g, '_cached_user'):
        return g._cached_user
    user_id = session.get('user_id')
    user = db.session.get(User, user_id) if user_id else None
    g._cached_user = user
    return user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            flash('请先登录', 'error')
            return redirect(url_for('login', next=request.url))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('is_admin'):
            flash('需要管理员权限', 'error')
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped
