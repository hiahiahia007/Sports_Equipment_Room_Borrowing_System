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
                
                # Reserve inventory
                equipment.available_quantity -= quantity
                
                record = BorrowRecord(
                    equipment=equipment,
                    user=user,
                    user_name=user_name,
                    quantity=quantity,
                    status='pending', # Initial status
                    borrow_date=None, # Not yet picked up
                )
                db.session.add(record)
                db.session.flush()
            return BorrowResult(record=record, equipment=equipment)
        except BorrowServiceError:
            raise
        except SQLAlchemyError as exc:
            current_app.logger.exception('Borrow transaction failed: %s', exc)
            db.session.rollback()
            raise BorrowServiceError('申请失败，请稍后再试。') from exc

    def approve_request(self, record_id: int) -> BorrowResult:
        try:
            with self._transaction():
                record = db.session.get(BorrowRecord, record_id)
                if not record:
                    raise BorrowServiceError('记录不存在。')
                if record.status != 'pending':
                    raise BorrowServiceError('该记录不是待审核状态。')
                
                record.status = 'approved'
            return BorrowResult(record=record, equipment=record.equipment)
        except BorrowServiceError:
            raise
        except SQLAlchemyError as exc:
            current_app.logger.exception('Approve failed: %s', exc)
            db.session.rollback()
            raise BorrowServiceError('审核失败。') from exc

    def reject_request(self, record_id: int) -> BorrowResult:
        try:
            with self._transaction():
                record = db.session.get(BorrowRecord, record_id)
                if not record:
                    raise BorrowServiceError('记录不存在。')
                if record.status != 'pending':
                    raise BorrowServiceError('该记录不是待审核状态。')
                
                record.status = 'rejected'
                # Release inventory
                if record.equipment:
                    record.equipment.available_quantity += record.quantity
            return BorrowResult(record=record, equipment=record.equipment)
        except BorrowServiceError:
            raise
        except SQLAlchemyError as exc:
            current_app.logger.exception('Reject failed: %s', exc)
            db.session.rollback()
            raise BorrowServiceError('拒绝失败。') from exc

    def confirm_pickup(self, record_id: int, days: int = 7) -> BorrowResult:
        try:
            with self._transaction():
                record = db.session.get(BorrowRecord, record_id)
                if not record:
                    raise BorrowServiceError('记录不存在。')
                if record.status != 'approved':
                    raise BorrowServiceError('该记录未通过审核或状态不正确。')
                
                now = datetime.datetime.now(datetime.timezone.utc)
                record.status = 'borrowed'
                record.borrow_date = now
                record.due_date = now + datetime.timedelta(days=days)
            return BorrowResult(record=record, equipment=record.equipment)
        except BorrowServiceError:
            raise
        except SQLAlchemyError as exc:
            current_app.logger.exception('Pickup failed: %s', exc)
            db.session.rollback()
            raise BorrowServiceError('确认借出失败。') from exc

    def return_record(
        self,
        *,
        record_id: int,
        acting_user: Optional[User],
        allow_admin_override: bool = True,
        is_damaged: bool = False,
    ) -> BorrowResult:
        try:
            with self._transaction():
                record = db.session.get(BorrowRecord, record_id)
                if not record:
                    raise BorrowServiceError('借用记录不存在。')
                if record.status == 'returned':
                    raise BorrowServiceError('该记录已归还。')
                
                # Allow return if it was just borrowed or in repair pending
                # But if it's pending or approved, it shouldn't be "returned", it should be cancelled/rejected.
                # Assuming this is for actual return of goods.
                
                if acting_user and record.user_id:
                    if record.user_id != acting_user.id and not (allow_admin_override and acting_user.is_admin):
                        raise BorrowServiceError('仅可操作自己的借用记录。')

                now = datetime.datetime.now(datetime.timezone.utc)
                record.return_date = now
                record.status = 'returned'
                record.is_damaged = is_damaged

                # Calculate Fine
                if record.due_date and now > record.due_date:
                    overdue_days = (now - record.due_date).days
                    if overdue_days > 0:
                        # 5 yuan per day
                        fine = overdue_days * 5.0
                        # Cap at equipment price
                        if record.equipment and record.equipment.price:
                            fine = min(fine, record.equipment.price)
                        record.fine = fine
                
                # Calculate Damage Cost
                if is_damaged and record.equipment and record.equipment.price:
                    record.damage_cost = record.equipment.price * 1.5

                # Release inventory
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

    def report_repair(self, record_id: int, acting_user: User) -> BorrowResult:
        try:
            with self._transaction():
                record = db.session.get(BorrowRecord, record_id)
                if not record:
                    raise BorrowServiceError('记录不存在。')
                if record.status != 'borrowed':
                    raise BorrowServiceError('当前状态无法报修。')
                
                if record.user_id != acting_user.id:
                    raise BorrowServiceError('只能报修自己的借用记录。')

                record.status = 'repair_pending'
            return BorrowResult(record=record, equipment=record.equipment)
        except BorrowServiceError:
            raise
        except SQLAlchemyError as exc:
            current_app.logger.exception('Repair report failed: %s', exc)
            db.session.rollback()
            raise BorrowServiceError('报修失败。') from exc
