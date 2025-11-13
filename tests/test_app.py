import pytest
from app import create_app
from models import db, Equipment, BorrowRecord

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
    # add equipment directly (admin-protected route in app)
    with app.app_context():
        eq = Equipment(name='足球', total_quantity=5, available_quantity=5)
        db.session.add(eq)
        db.session.commit()
        eq = Equipment.query.filter_by(name='足球').first()
        assert eq is not None
        assert eq.available_quantity == 5

    # borrow 2
    resp = client.post('/borrow', data={'equipment_id': str(eq.id), 'user_name': 'Alice', 'quantity': '2'}, follow_redirects=True)
    assert resp.status_code in (200, 302)
    with app.app_context():
        eq = Equipment.query.get(eq.id)
        assert eq.available_quantity == 3
        rec = BorrowRecord.query.filter_by(user_name='Alice').first()
        assert rec is not None
        assert rec.quantity == 2
        assert rec.return_date is None

    # borrow too many should not reduce
    resp = client.post('/borrow', data={'equipment_id': str(eq.id), 'user_name': 'Bob', 'quantity': '10'}, follow_redirects=True)
    assert resp.status_code in (200, 302)
    with app.app_context():
        eq = Equipment.query.get(eq.id)
        assert eq.available_quantity == 3

    # return
    with app.app_context():
        rec = BorrowRecord.query.filter_by(user_name='Alice').first()
        rid = rec.id
    resp = client.post('/return', data={'record_id': str(rid)}, follow_redirects=True)
    assert resp.status_code in (200, 302)
    with app.app_context():
        rec = BorrowRecord.query.get(rid)
        assert rec.return_date is not None
        eq = Equipment.query.get(eq.id)
        assert eq.available_quantity == 5
