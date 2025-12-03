from app import create_app
from models import db, Equipment, User

app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:', 'WTF_CSRF_ENABLED': False})
with app.app_context():
    db.create_all()
    eq = Equipment(name='篮球', total_quantity=5, available_quantity=5)
    db.session.add(eq)
    user = User(username='test_user', password_hash='hash', is_admin=False)
    db.session.add(user)
    db.session.commit()

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user_id'] = user.id

    resp = client.post('/borrow', data={
        'equipment_id': eq.id,
        'quantity': 1,
        'user_name': 'test_user',
    }, follow_redirects=True)
    print('status', resp.status_code)
    eq = Equipment.query.get(eq.id)
    print('available', eq.available_quantity)
