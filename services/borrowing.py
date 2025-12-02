"""Borrowing domain service logic."""
from __future__ import annotations

import datetime
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

from flask import current_app
from sqlalchemy.exc import InvalidRequestError, SQLAlchemyError

from models import db, Equipment, BorrowRecord, User


class BorrowServiceError(RuntimeError):
    """Base class for borrow/return failures."""


@dataclass(frozen=True)
class BorrowResult:
    record: BorrowRecord
    equipment: Equipment


class BorrowService:
    """Encapsulates borrowing related business logic with transaction handling."""

    @contextmanager
    def _transaction(self):
        try:
            with db.session.begin():
                yield
        except InvalidRequestError:
            with db.session.begin_nested():
                yield

    def borrow(
        self,
        *,
        equipment_id: int,
        quantity: int,
        user_name: str,
        user: Optional[User] = None,
    ) -> BorrowResult:
        if quantity <= 0:
            raise BorrowServiceError('借用数量必须大于 0。')
        try:
            with self._transaction():
                equipment = db.session.get(Equipment, equipment_id)
                if not equipment:
                    raise BorrowServiceError('所选设备不存在。')
                if equipment.available_quantity < quantity:
                    raise BorrowServiceError('可借数量不足。')
                equipment.available_quantity -= quantity
                record = BorrowRecord(
                    equipment=equipment,
                    user=user,
                    user_name=user_name,
                    quantity=quantity,
                )
                db.session.add(record)
                db.session.flush()
            return BorrowResult(record=record, equipment=equipment)
        except BorrowServiceError:
            raise
        except SQLAlchemyError as exc:
            current_app.logger.exception('Borrow transaction failed: %s', exc)
            db.session.rollback()
            raise BorrowServiceError('借用失败，请稍后再试。') from exc

    def return_record(
        self,
        *,
        record_id: int,
        acting_user: Optional[User],
        allow_admin_override: bool = True,
    ) -> BorrowResult:
        try:
            with self._transaction():
                record = db.session.get(BorrowRecord, record_id)
                if not record:
                    raise BorrowServiceError('借用记录不存在。')
                if record.return_date is not None:
                    raise BorrowServiceError('该记录已归还。')

                if acting_user and record.user_id:
                    if record.user_id != acting_user.id and not (allow_admin_override and acting_user.is_admin):
                        raise BorrowServiceError('仅可操作自己的借用记录。')

                record.return_date = datetime.datetime.now(datetime.timezone.utc)
                equipment = record.equipment
                if equipment:
                    equipment.available_quantity += record.quantity
            return BorrowResult(record=record, equipment=record.equipment)
        except BorrowServiceError:
            raise
        except SQLAlchemyError as exc:
            current_app.logger.exception('Return transaction failed: %s', exc)
            db.session.rollback()
            raise BorrowServiceError('归还失败，请稍后再试。') from exc
