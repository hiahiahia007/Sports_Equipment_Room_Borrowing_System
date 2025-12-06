import pytest
from app import create_app
from models import db, Equipment, BorrowRecord, User
from services.borrowing import BorrowService, BorrowServiceError

@pytest.fixture
def app():
    app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'})
    with app.app_context():
        # create_app already initializes the db (db.init_app). Just create tables for the test DB.
        db.create_all()
        yield app

@pytest.fixture
def client(app):
    return app.test_client()

def test_add_and_borrow_and_return(client, app):
    service = BorrowService()
    with app.app_context():
        # add equipment directly (admin-protected route in app)
        eq = Equipment(name='足球', total_quantity=5, available_quantity=5)
        admin = User(username='admin', password_hash='hash', is_admin=True)
        db.session.add_all([eq, admin])
        db.session.commit()
        equipment_id = eq.id
        admin_id = admin.id

        # borrow 2
        resp = client.post('/borrow', data={'equipment_id': str(equipment_id), 'user_name': 'Alice', 'quantity': '2'}, follow_redirects=True)
        assert resp.status_code in (200, 302)

        eq = db.session.get(Equipment, equipment_id)
        rec = BorrowRecord.query.filter_by(user_name='Alice').first()
        assert rec is not None
        assert rec.quantity == 2
        assert rec.status == 'pending'
        assert eq.available_quantity == 5  # 尚未扣减库存
        alice_record_id = rec.id

        admin = db.session.get(User, admin_id)
        service.approve_request(record_id=alice_record_id, approver=admin)
        eq = db.session.get(Equipment, equipment_id)
        assert eq.available_quantity == 3
        service.mark_checked_out(record_id=alice_record_id, operator=admin)
        rec = db.session.get(BorrowRecord, alice_record_id)
        assert rec.status == 'checked_out'

        # borrow too many should not reduce
        resp = client.post('/borrow', data={'equipment_id': str(equipment_id), 'user_name': 'Bob', 'quantity': '10'}, follow_redirects=True)
        assert resp.status_code in (200, 302)
        eq = db.session.get(Equipment, equipment_id)
        assert eq.available_quantity == 3
        rec = BorrowRecord.query.filter_by(user_name='Bob').first()
        assert rec.status == 'pending'
        with pytest.raises(BorrowServiceError):
            service.approve_request(record_id=rec.id, approver=admin)

        # return
        rec = db.session.get(BorrowRecord, alice_record_id)
        rid = rec.id
        with client.session_transaction() as sess:
            sess['user_id'] = admin_id
            sess['is_admin'] = True
        resp = client.post('/return', data={'record_id': str(rid)}, follow_redirects=True)
        assert resp.status_code in (200, 302)
        rec = db.session.get(BorrowRecord, rid)
        assert rec.return_date is not None
        eq = db.session.get(Equipment, equipment_id)
        assert eq.available_quantity == 5
