from app import create_app
from models import db, Equipment, BorrowRecord

app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'})
with app.app_context():
    db.create_all()
    e = Equipment(name='乒乓球', total_quantity=10, available_quantity=10)
    db.session.add(e)
    db.session.commit()
    # borrow 3
    e2 = db.session.get(Equipment, e.id)
    if e2.available_quantity != 10:
        print('FAIL: initial available')
    e2.available_quantity -= 3
    rec = BorrowRecord(equipment=e2, user_name='Test', quantity=3)
    db.session.add(rec)
    db.session.commit()
    e3 = db.session.get(Equipment, e.id)
    if e3.available_quantity != 7:
        print('FAIL: after borrow', e3.available_quantity)
    else:
        print('SMOKE PASS')
