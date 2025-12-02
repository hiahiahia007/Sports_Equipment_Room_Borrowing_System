#!/usr/bin/env python3
"""
Create or update an admin user for the sports equipment system.
Usage:
  python create_admin.py --username admin --password secret

This script must be run from the project root and will use the app's SQLAlchemy
configuration. It creates the user if missing, sets is_admin=True and sets the
password hash to the provided password.
"""
import argparse
import os
import sys

from werkzeug.security import generate_password_hash

# Import application factory
from app import create_app
from models import db, User


def main(argv=None):
    parser = argparse.ArgumentParser(description='Create or update an admin user')
    parser.add_argument('--username', '-u', required=True, help='admin username')
    parser.add_argument('--password', '-p', required=True, help='admin password')
    parser.add_argument('--db-uri', help='optional DB URI to override app config')
    args = parser.parse_args(argv)

    config = {}
    if args.db_uri:
        config['SQLALCHEMY_DATABASE_URI'] = args.db_uri

    app = create_app(config)
    with app.app_context():
        db.create_all()
        user = User.query.filter_by(username=args.username).first()
        if not user:
            user = User(username=args.username, password_hash=generate_password_hash(args.password), is_admin=True)
            db.session.add(user)
            db.session.commit()
            print(f"Created new admin user: {args.username}")
            return 0
        else:
            # update
            user.password_hash = generate_password_hash(args.password)
            user.is_admin = True
            db.session.commit()
            print(f"Updated existing user '{args.username}' to admin and set new password")
            return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        print('Error:', e)
        sys.exit(1)
