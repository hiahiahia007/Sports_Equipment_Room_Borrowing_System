import re
from app import create_app
from models import db

app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
with app.app_context():
    db.create_all()
    client = app.test_client()
    r = client.get('/register')
    print('/register GET status', r.status_code)
    html = r.get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    print('csrf token found on /register?', bool(m))
    print('register snippet:', html[:300])

    # create user via POST using token if present
    data = {'username':'smoke_user','password':'pass123', 'full_name':'S User', 'class_name':'C1', 'gender':'male', 'phone':'123456'}
    if m:
        data['csrf_token'] = m.group(1)
    r2 = client.post('/register', data=data, follow_redirects=True)
    print('/register POST status', r2.status_code)
    # create equipment
    from models import Equipment
    e = Equipment(name='SmokeBall', total_quantity=3, available_quantity=3)
    db.session.add(e); db.session.commit()
    # get catalog (should be accessible after register/login)
    r3 = client.get('/catalog')
    print('/catalog GET status', r3.status_code)
    html3 = r3.get_data(as_text=True)
    m2 = re.search(r'name="csrf_token" value="([^"]+)"', html3)
    print('csrf token found on /catalog?', bool(m2))
    borrow_data = {'equipment_id': str(e.id), 'quantity':'1'}
    if m2:
        borrow_data['csrf_token'] = m2.group(1)
    r4 = client.post('/borrow', data=borrow_data, follow_redirects=True)
    print('/borrow POST status', r4.status_code)
    print('Borrow success flash present?', '借出成功' in r4.get_data(as_text=True))
