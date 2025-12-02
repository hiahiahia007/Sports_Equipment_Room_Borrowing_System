import datetime
from datetime import timezone
from flask_sqlalchemy import SQLAlchemy

# SQLAlchemy instance (initialized by app)
db = SQLAlchemy()

class Equipment(db.Model):
    __tablename__ = 'equipment'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    total_quantity = db.Column(db.Integer, nullable=False, default=1)
    available_quantity = db.Column(db.Integer, nullable=False, default=1)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'total_quantity': self.total_quantity,
            'available_quantity': self.available_quantity,
        }

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    # additional profile fields
    full_name = db.Column(db.String(120), nullable=True)
    class_name = db.Column(db.String(120), nullable=True)
    gender = db.Column(db.String(16), nullable=True)
    phone = db.Column(db.String(30), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'full_name': self.full_name,
            'class_name': self.class_name,
            'gender': self.gender,
            'phone': self.phone,
        }

class BorrowRecord(db.Model):
    __tablename__ = 'borrow_record'
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    equipment = db.relationship('Equipment', backref=db.backref('borrow_records', lazy=True))
    user = db.relationship('User', backref=db.backref('borrow_records', lazy=True))
    user_name = db.Column(db.String(120), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    # use timezone-aware UTC timestamps
    borrow_date = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    return_date = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'equipment_id': self.equipment_id,
            'equipment_name': self.equipment.name if self.equipment else None,
            'user_name': self.user_name,
            'user_id': self.user_id,
            'quantity': self.quantity,
            'borrow_date': self.borrow_date.isoformat() if self.borrow_date else None,
            'return_date': self.return_date.isoformat() if self.return_date else None,
        }


class NewsPost(db.Model):
    __tablename__ = 'news_post'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    summary = db.Column(db.String(300), nullable=True)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(40), nullable=False, default='campus')
    source = db.Column(db.String(255), nullable=True)
    published_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    is_pinned = db.Column(db.Boolean, default=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_by = db.relationship('User', backref=db.backref('news_posts', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'summary': self.summary,
            'content': self.content,
            'category': self.category,
            'source': self.source,
            'published_at': self.published_at.isoformat() if self.published_at else None,
            'is_pinned': self.is_pinned,
        }


class NewsComment(db.Model):
    __tablename__ = 'news_comment'
    id = db.Column(db.Integer, primary_key=True)
    news_id = db.Column(db.Integer, db.ForeignKey('news_post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))

    news = db.relationship('NewsPost', backref=db.backref('comments', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User')

    def to_dict(self):
        return {
            'id': self.id,
            'news_id': self.news_id,
            'user_id': self.user_id,
            'content': self.content,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
