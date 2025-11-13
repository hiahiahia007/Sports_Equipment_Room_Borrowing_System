import os
from app import create_app

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)
    print('Removed existing app.db')
app = create_app()
with app.app_context():
    from models import db
    db.create_all()
    print('Recreated database (app.db)')
