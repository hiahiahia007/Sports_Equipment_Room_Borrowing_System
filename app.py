from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import os
import datetime
from datetime import timezone

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')
DB_URI = f'sqlite:///{DB_PATH}'

def create_app(test_config=None):
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # secret key for flashing messages (development)
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret-key')
    # session & security defaults
    app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
    app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
    # set SESSION_COOKIE_SECURE when running under HTTPS (env-controlled)
    if os.environ.get('FORCE_SECURE_COOKIES') == '1':
        app.config['SESSION_COOKIE_SECURE'] = True

    if test_config:
        app.config.update(test_config)

    # initialize DB object and models
    from models import db, Equipment, BorrowRecord, User
    from werkzeug.security import generate_password_hash, check_password_hash
    db.init_app(app)
    # CSRF protection for all POST endpoints and forms (optional import)
    try:
        from flask_wtf import CSRFProtect
        csrf = CSRFProtect()
        csrf.init_app(app)
        # expose csrf_token() to templates (generates token on GET so forms can render it)
        @app.context_processor
        def inject_csrf_token():
            try:
                from flask_wtf.csrf import generate_csrf
                return {'csrf_token': generate_csrf}
            except Exception:
                # if flask_wtf not available or something fails, provide a noop to avoid template errors
                return {'csrf_token': lambda: ''}
    except Exception:
        # Minimal, dependency-free CSRF implementation using session.
        # This ensures the app is runnable even if Flask-WTF isn't installed.
        import secrets
        from flask import session

        def generate_csrf():
            tok = session.get('_csrf_token')
            if not tok:
                tok = secrets.token_urlsafe(16)
                session['_csrf_token'] = tok
            return tok

        @app.context_processor
        def inject_csrf_token_simple():
            return {'csrf_token': generate_csrf}

        @app.before_request
        def verify_csrf_token():
            # Only validate for non-API POST requests (forms). Skip safe methods.
            if request.method == 'POST' and not request.path.startswith('/api/'):
                # get token from form data (standard) or headers
                form_token = request.form.get('csrf_token') if request.form else None
                header_token = request.headers.get('X-CSRF-Token')
                token = form_token or header_token
                if not token or token != session.get('_csrf_token'):
                    # If it's an AJAX JSON POST, allow if X-CSRF-Token matches
                    # Otherwise abort with 400
                    from flask import abort
                    abort(400, description='Missing or invalid CSRF token')

    # expose current_user to templates
    @app.context_processor
    def inject_user():
        from flask import session
        user = None
        if session.get('user_id'):
            # use session.get with db.session.get to avoid legacy Query.get warnings
            try:
                user = db.session.get(User, session.get('user_id'))
            except Exception:
                # fallback to legacy query for older SQLAlchemy
                user = User.query.get(session.get('user_id'))
        return {'current_user': user, 'current_year': datetime.datetime.now().year}

    def login_user(user):
        from flask import session
        session['user_id'] = user.id
        session['is_admin'] = bool(user.is_admin)

    def logout_user():
        from flask import session
        session.pop('user_id', None)
        session.pop('is_admin', None)

    def login_required(f):
        from functools import wraps
        from flask import session, flash, redirect, url_for, request
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not session.get('user_id'):
                flash('请先登录', 'error')
                return redirect(url_for('login', next=request.url))
            return f(*args, **kwargs)
        return wrapped

    def admin_required(f):
        from functools import wraps
        from flask import session, flash, redirect, url_for
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not session.get('is_admin'):
                flash('需要管理员权限', 'error')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapped

    # Set some basic security headers on every response
    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'no-referrer-when-downgrade')
        # minimal CSP allowing same-origin resources and bootstrap CDN fonts
        response.headers.setdefault('Content-Security-Policy', "default-src 'self' https:; script-src 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; font-src 'self' https: data:;")
        return response

    @app.route('/')
    def index():
        # If not logged in, show login page first; otherwise go to catalog
        from flask import session
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return redirect(url_for('catalog'))

    @app.route('/catalog')
    @login_required
    def catalog():
        # simple search and pagination
        q = request.args.get('q', '').strip()
        page = int(request.args.get('page', 1))
        per_page = 10
        query = Equipment.query
        if q:
            query = query.filter(Equipment.name.ilike(f"%{q}%"))
        total = query.count()
        items = query.order_by(Equipment.name).offset((page-1)*per_page).limit(per_page).all()
        return render_template('catalog.html', equipments=items, q=q, page=page, per_page=per_page, total=total)

    @app.route('/equipment/<int:equipment_id>')
    @login_required
    def equipment_detail(equipment_id):
        eq = db.session.get(Equipment, equipment_id)
        if not eq:
            flash('设备未找到', 'error')
            return redirect(url_for('catalog'))
        # recent borrow records for this equipment
        recs = BorrowRecord.query.filter_by(equipment_id=eq.id).order_by(BorrowRecord.borrow_date.desc()).limit(50).all()
        return render_template('equipment_detail.html', equipment=eq, records=recs)

    @app.route('/add_equipment', methods=['POST'])
    def add_equipment():
        # only admin can add equipment
        from flask import session
        if not session.get('is_admin'):
            flash('需要管理员权限添加设备', 'error')
            return redirect(url_for('admin'))
        name = request.form.get('name')
        total = int(request.form.get('total', 1))
        if not name:
            return redirect(url_for('admin'))
        eq = Equipment(name=name, total_quantity=total, available_quantity=total)
        db.session.add(eq)
        db.session.commit()
        flash(f'已添加设备：{name}（总量 {total}）', 'success')
        # redirect back to admin and include added_id so frontend can highlight the new row
        return redirect(url_for('admin', added_id=eq.id))

    @app.route('/borrow', methods=['POST'])
    @login_required
    def borrow():
        try:
            equipment_id = int(request.form.get('equipment_id'))
        except (ValueError, TypeError):
            flash('错误：请选择有效的设备。', 'error')
            return redirect(url_for('index'))
        # logged-in user is required; use their username
        from flask import session
        user = None
        if session.get('user_id'):
            user = db.session.get(User, session.get('user_id'))
        # allow tests or API callers to supply a user_name in the form when not logged in
        user_name = request.form.get('user_name')
        if not user:
            if not user_name:
                flash('请先登录以执行借用', 'error')
                return redirect(url_for('login'))
            # anonymous/form-provided borrow: user remains None, user_name comes from form
        else:
            # prefer the logged-in user's username when available
            user_name = user.username
        quantity = int(request.form.get('quantity', 1))
        eq = db.session.get(Equipment, equipment_id)
        if not eq or quantity <= 0:
            flash('错误：设备不存在或借用数量不正确。', 'error')
            return redirect(url_for('index'))
        if eq.available_quantity < quantity:
            # not enough
            flash('借用失败：可借数量不足。', 'error')
            return redirect(url_for('index'))
        eq.available_quantity -= quantity
        record = BorrowRecord(equipment=eq, user_name=user_name, quantity=quantity)
        if user:
            record.user = user
        db.session.add(record)
        db.session.commit()
        flash(f'借出成功：{user_name} 借用 {quantity} 个 {eq.name}', 'success')
        return redirect(url_for('catalog'))

    @app.route('/register', methods=['GET','POST'])
    def register():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            if not username or not password:
                flash('用户名和密码不能为空', 'error')
                return redirect(url_for('register'))
            if User.query.filter_by(username=username).first():
                flash('用户名已存在', 'error')
                return redirect(url_for('register'))
            pw_hash = generate_password_hash(password)
            # collect profile fields
            full_name = request.form.get('full_name')
            class_name = request.form.get('class_name')
            gender = request.form.get('gender')
            phone = request.form.get('phone')
            user = User(username=username, password_hash=pw_hash, is_admin=False,
                        full_name=full_name, class_name=class_name, gender=gender, phone=phone)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('注册并登录成功', 'success')
            return redirect(url_for('catalog'))
        return render_template('register.html')

    @app.route('/login', methods=['GET','POST'])
    def login():
        from flask import session
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            # allow fallback admin password via env
            admin_pass = os.environ.get('ADMIN_PASS')
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                flash('登录成功', 'success')
                # respect next param if provided (basic safety check)
                next_url = request.args.get('next') or request.form.get('next')
                if next_url and next_url.startswith('/'):
                    return redirect(next_url)
                return redirect(url_for('catalog'))
            elif username == os.environ.get('ADMIN_USER') and admin_pass and password == admin_pass:
                admin_user = User.query.filter_by(username=username).first()
                if not admin_user:
                    admin_user = User(username=username, password_hash=generate_password_hash(password), is_admin=True)
                    db.session.add(admin_user)
                    db.session.commit()
                login_user(admin_user)
                flash('管理员登录成功', 'success')
                next_url = request.args.get('next') or request.form.get('next')
                if next_url and next_url.startswith('/'):
                    return redirect(next_url)
                return redirect(url_for('admin'))
            else:
                flash('用户名或密码错误', 'error')
                return redirect(url_for('login'))
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        logout_user()
        flash('已登出', 'success')
        return redirect(url_for('catalog'))

    @app.route('/profile')
    def profile():
        from flask import session
        if not session.get('user_id'):
            flash('请先登录', 'error')
            return redirect(url_for('login'))
        user = db.session.get(User, session.get('user_id'))
        # all borrow records for this user
        borrows_q = BorrowRecord.query.filter_by(user_id=user.id)
        total_borrows = borrows_q.count()
        outstanding = borrows_q.filter(BorrowRecord.return_date.is_(None)).count()
        recent = borrows_q.order_by(BorrowRecord.borrow_date.desc()).limit(50).all()
        return render_template('profile.html', user=user, borrows=recent, total_borrows=total_borrows, outstanding=outstanding)

    @app.route('/profile/edit', methods=['GET','POST'])
    @login_required
    def edit_profile():
        from flask import session
        user = db.session.get(User, session.get('user_id'))
        if request.method == 'POST':
            user.full_name = request.form.get('full_name')
            user.class_name = request.form.get('class_name')
            user.gender = request.form.get('gender')
            user.phone = request.form.get('phone')
            db.session.commit()
            flash('个人资料已更新', 'success')
            return redirect(url_for('profile'))
        return render_template('profile_edit.html', user=user)

    @app.route('/return', methods=['POST'])
    def do_return():
        record_id = int(request.form.get('record_id'))
        record = db.session.get(BorrowRecord, record_id)
        if not record or record.return_date is not None:
            return redirect(url_for('catalog'))
        # permission: admin can return any; user can return own
        from flask import session
        if session.get('user_id') and record.user_id and record.user_id != session.get('user_id') and not session.get('is_admin'):
            flash('只能归还自己的借出记录', 'error')
            return redirect(url_for('catalog'))
        record.return_date = datetime.datetime.now(timezone.utc)
        eq = record.equipment
        eq.available_quantity += record.quantity
        db.session.commit()
        flash(f'归还成功：{record.user_name} 归还 {record.quantity} 个 {eq.name}', 'success')
        return redirect(url_for('catalog'))

    # Minimal JSON API endpoints
    @app.route('/api/equipment', methods=['GET'])
    def api_equipment():
        items = [e.to_dict() for e in Equipment.query.order_by(Equipment.name).all()]
        return jsonify(items)

    @app.route('/records')
    @login_required
    def records():
        # Show records. Admins see all; normal users see only their own records.
        from flask import session
        status = request.args.get('status')  # all | returned | outstanding
        user = None
        if session.get('user_id'):
            user = db.session.get(User, session.get('user_id'))

        if user and user.is_admin:
            query = BorrowRecord.query.join(Equipment)
        else:
            # restrict to current user's records
            query = BorrowRecord.query.join(Equipment).filter(BorrowRecord.user_id == (user.id if user else None))

        if status == 'returned':
            query = query.filter(BorrowRecord.return_date.isnot(None))
        elif status == 'outstanding':
            query = query.filter(BorrowRecord.return_date.is_(None))

        items = query.order_by(BorrowRecord.borrow_date.desc()).limit(200).all()
        return render_template('records.html', borrows=items, status=status)

    @app.route('/export_records')
    @login_required
    def export_records():
        # export all records as CSV
        import io, csv
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['id', 'equipment', 'user_name', 'quantity', 'borrow_date', 'return_date'])
        for r in BorrowRecord.query.order_by(BorrowRecord.borrow_date.desc()).all():
            cw.writerow([r.id, r.equipment.name if r.equipment else '', r.user_name, r.quantity, r.borrow_date, r.return_date or ''])
        output = si.getvalue()
        return app.response_class(output, mimetype='text/csv', headers={'Content-Disposition':'attachment;filename=borrow_records.csv'})

    @app.route('/export_my_records')
    @login_required
    def export_my_records():
        # export current user's records as CSV
        import io, csv
        from flask import session
        user = None
        if session.get('user_id'):
            user = db.session.get(User, session.get('user_id'))
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['id', 'equipment', 'user_name', 'quantity', 'borrow_date', 'return_date'])
        # allow admin to export another user's records by ?user_id=
        target_user_id = request.args.get('user_id')
        qs = []
        if target_user_id and session.get('is_admin'):
            try:
                tuid = int(target_user_id)
                qs = BorrowRecord.query.filter_by(user_id=tuid).order_by(BorrowRecord.borrow_date.desc()).all()
            except Exception:
                qs = []
        elif user:
            qs = BorrowRecord.query.filter_by(user_id=user.id).order_by(BorrowRecord.borrow_date.desc()).all()
        for r in qs:
            cw.writerow([r.id, r.equipment.name if r.equipment else '', r.user_name, r.quantity, r.borrow_date, r.return_date or ''])
        output = si.getvalue()
        return app.response_class(output, mimetype='text/csv', headers={'Content-Disposition':'attachment;filename=my_borrow_records.csv'})

    # simple admin auth (session-based)
    @app.route('/admin', methods=['GET','POST'])
    def admin():
        from flask import session
        admin_pass = os.environ.get('ADMIN_PASS', 'admin')
        if request.method == 'POST':
            pw = request.form.get('password')
            if pw == admin_pass:
                session['is_admin'] = True
                flash('管理员登录成功', 'success')
                return redirect(url_for('admin'))
            else:
                flash('密码错误', 'error')
                return redirect(url_for('admin'))
        is_admin = session.get('is_admin', False)
        equipments = []
        users = []
        if is_admin:
            equipments = Equipment.query.order_by(Equipment.name).all()
            # support simple search/filter on users via ?q=
            q = request.args.get('q', '').strip()
            user_query = User.query
            if q:
                user_query = user_query.filter(
                    (User.username.ilike(f"%{q}%")) |
                    (User.full_name.ilike(f"%{q}%")) |
                    (User.class_name.ilike(f"%{q}%"))
                )
            users = user_query.order_by(User.username).all()
        return render_template('admin.html', is_admin=is_admin, equipments=equipments, users=users)

    @app.route('/admin/user/<int:user_id>')
    @admin_required
    def admin_view_user(user_id):
        user = db.session.get(User, user_id)
        if not user:
            flash('用户未找到', 'error')
            return redirect(url_for('admin'))
        records = BorrowRecord.query.filter_by(user_id=user.id).order_by(BorrowRecord.borrow_date.desc()).all()
        return render_template('admin_user.html', user=user, records=records)

    @app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
    @admin_required
    def edit_user(user_id):
        user = db.session.get(User, user_id)
        if not user:
            flash('用户未找到', 'error')
            return redirect(url_for('admin'))
        # update profile fields
        user.full_name = request.form.get('full_name')
        user.class_name = request.form.get('class_name')
        user.gender = request.form.get('gender')
        user.phone = request.form.get('phone')
        db.session.commit()
        flash('用户信息已更新', 'success')
        return redirect(url_for('admin_view_user', user_id=user.id))

    @app.route('/admin/edit_equipment/<int:eq_id>', methods=['POST'])
    @admin_required
    def edit_equipment(eq_id):
        from flask import session
        if not session.get('is_admin'):
            flash('需要管理员权限', 'error')
            return redirect(url_for('admin'))
        eq = db.session.get(Equipment, eq_id)
        if not eq:
            flash('设备未找到', 'error')
            return redirect(url_for('admin'))
        # update total and adjust available accordingly
        try:
            total = int(request.form.get('total', eq.total_quantity))
        except (ValueError, TypeError):
            total = eq.total_quantity
        # adjust available by difference
        diff = total - eq.total_quantity
        eq.total_quantity = total
        eq.available_quantity = max(0, eq.available_quantity + diff)
        db.session.commit()
        flash('设备已更新', 'success')
        return redirect(url_for('admin'))

    @app.route('/admin/delete_equipment/<int:eq_id>', methods=['POST'])
    @admin_required
    def delete_equipment(eq_id):
        from flask import session
        if not session.get('is_admin'):
            flash('需要管理员权限', 'error')
            return redirect(url_for('admin'))
        eq = db.session.get(Equipment, eq_id)
        if not eq:
            flash('设备未找到', 'error')
            return redirect(url_for('admin'))
        # prevent deletion if outstanding borrows
        outstanding = BorrowRecord.query.filter_by(equipment_id=eq.id, return_date=None).count()
        if outstanding:
            flash('存在未归还记录，无法删除', 'error')
            return redirect(url_for('admin'))
        db.session.delete(eq)
        db.session.commit()
        flash('设备已删除', 'success')
        return redirect(url_for('admin'))

    @app.route('/api/borrow', methods=['POST'])
    def api_borrow():
        data = request.get_json() or {}
        equipment_id = data.get('equipment_id')
        user_name = data.get('user_name')
        quantity = int(data.get('quantity', 1))
        eq = db.session.get(Equipment, equipment_id)
        if not eq:
            return jsonify({'error': 'equipment not found'}), 404
        if eq.available_quantity < quantity:
            return jsonify({'error': 'not enough available'}), 400
        eq.available_quantity -= quantity
        record = BorrowRecord(equipment=eq, user_name=user_name, quantity=quantity)
        db.session.add(record)
        db.session.commit()
        return jsonify(record.to_dict()), 201

    @app.route('/api/return', methods=['POST'])
    def api_return():
        data = request.get_json() or {}
        record_id = data.get('record_id')
        record = db.session.get(BorrowRecord, record_id)
        if not record:
            return jsonify({'error': 'record not found'}), 404
        if record.return_date is not None:
            return jsonify({'error': 'already returned'}), 400
        record.return_date = datetime.datetime.now(timezone.utc)
        record.equipment.available_quantity += record.quantity
        db.session.commit()
        return jsonify(record.to_dict())

    return app

if __name__ == '__main__':
    app = create_app()
    # ensure DB file exists and tables created
    from models import db
    with app.app_context():
        db.create_all()
    app.run(debug=True)
