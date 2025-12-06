from __future__ import annotations

import csv
import datetime
import io
import os

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from config import BaseConfig, config_by_name
from models import BorrowRecord, Equipment, NewsComment, NewsPost, User, db
from sqlalchemy import or_
from services.auth import (
    admin_required,
    get_current_user,
    login_required,
    login_user,
    logout_user,
)
from services.borrowing import BorrowService, BorrowServiceError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join('static', 'equipment_images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


NEWS_CATEGORY_LABELS = {
    'campus': '体育器材室资讯',
    'national': '国家体育资讯',
    'event': '赛事速递',
}


def _load_config(app: Flask, config_name: str | None, test_config: dict | None) -> None:
    resolved_name = config_name or os.environ.get('FLASK_CONFIG', 'development')
    config_cls = config_by_name.get(resolved_name, BaseConfig)
    app.config.from_object(config_cls)
    if test_config:
        app.config.update(test_config)


def create_app(config_name: str | None = None, test_config: dict | None = None):
    if isinstance(config_name, dict) and test_config is None:
        test_config = config_name
        config_name = None
    app = Flask(__name__)
    _load_config(app, config_name, test_config)
    db.init_app(app)
    borrow_service = BorrowService()

    def resolve_publish_time(raw_value: str | None):
        if not raw_value:
            return datetime.datetime.now(datetime.timezone.utc)
        try:
            parsed = datetime.datetime.fromisoformat(raw_value)
        except ValueError:
            return datetime.datetime.now(datetime.timezone.utc)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed

    try:
        from flask_wtf import CSRFProtect

        csrf = CSRFProtect()
        csrf.init_app(app)

        @app.context_processor
        def inject_csrf_token():
            try:
                from flask_wtf.csrf import generate_csrf

                return {'csrf_token': generate_csrf}
            except Exception:
                return {'csrf_token': lambda: ''}
    except Exception:
        import secrets
        from flask import session

        def generate_csrf():
            token = session.get('_csrf_token')
            if not token:
                token = secrets.token_urlsafe(16)
                session['_csrf_token'] = token
            return token

        @app.context_processor
        def inject_csrf_token_simple():
            return {'csrf_token': generate_csrf}

        @app.before_request
        def verify_csrf_token():
            if app.testing:
                return
            if request.method == 'POST' and not request.path.startswith('/api/'):
                form_token = request.form.get('csrf_token') if request.form else None
                header_token = request.headers.get('X-CSRF-Token')
                token = form_token or header_token
                if not token or token != session.get('_csrf_token'):
                    abort(400, description='Missing or invalid CSRF token')

    @app.before_request
    def bind_current_user():
        g.current_user = get_current_user()

    @app.context_processor
    def inject_user():
        return {
            'current_user': getattr(g, 'current_user', None),
            'current_year': datetime.datetime.now().year,
            'news_categories': NEWS_CATEGORY_LABELS,
        }

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'no-referrer-when-downgrade')
        response.headers.setdefault(
            'Content-Security-Policy',
            "default-src 'self' https:; script-src 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; font-src 'self' https: data:; img-src 'self' https: data:;",
        )
        return response

    @app.route('/')
    def index():
        equipment_total = Equipment.query.count()
        outstanding = BorrowRecord.query.filter(BorrowRecord.return_date.is_(None)).count()
        user_total = User.query.filter_by(is_admin=False).count()
        stats = {
            'equipment_total': equipment_total,
            'outstanding': outstanding,
            'user_total': user_total,
        }
        campus_news = (
            NewsPost.query.filter_by(category='campus')
            .order_by(NewsPost.is_pinned.desc(), NewsPost.published_at.desc())
            .limit(3)
            .all()
        )
        national_news = (
            NewsPost.query.filter_by(category='national')
            .order_by(NewsPost.is_pinned.desc(), NewsPost.published_at.desc())
            .limit(3)
            .all()
        )
        event_news = (
            NewsPost.query.filter_by(category='event')
            .order_by(NewsPost.is_pinned.desc(), NewsPost.published_at.desc())
            .limit(4)
            .all()
        )
        latest_comments = (
            NewsComment.query.order_by(NewsComment.created_at.desc()).limit(4).all()
        )
        return render_template(
            'index.html',
            stats=stats,
            campus_news=campus_news,
            national_news=national_news,
            event_news=event_news,
            latest_comments=latest_comments,
        )

    @app.route('/news')
    def news_list():
        category = request.args.get('category')
        q = (request.args.get('q') or '').strip()
        query = NewsPost.query.order_by(NewsPost.is_pinned.desc(), NewsPost.published_at.desc())
        if category and category in NEWS_CATEGORY_LABELS:
            query = query.filter_by(category=category)
        if q:
            like_value = f"%{q}%"
            query = query.filter(
                or_(
                    NewsPost.title.ilike(like_value),
                    NewsPost.summary.ilike(like_value),
                    NewsPost.content.ilike(like_value),
                )
            )
        posts = query.all()
        category_label = NEWS_CATEGORY_LABELS.get(category, '全部资讯') if category else '全部资讯'
        return render_template('news_list.html', posts=posts, active_category=category, category_label=category_label, q=q)

    @app.route('/news/<int:news_id>')
    def news_detail(news_id: int):
        news = db.session.get(NewsPost, news_id)
        if not news:
            flash('资讯不存在', 'error')
            return redirect(url_for('news_list'))
        comments = news.comments.order_by(NewsComment.created_at.desc()).all()
        return render_template('news_detail.html', news=news, comments=comments)

    @app.route('/news/<int:news_id>/comment', methods=['POST'])
    @login_required
    def add_news_comment(news_id: int):
        news = db.session.get(NewsPost, news_id)
        if not news:
            flash('资讯不存在', 'error')
            return redirect(url_for('news_list'))
        content = (request.form.get('content') or '').strip()
        if not content:
            flash('评论内容不能为空', 'error')
            return redirect(url_for('news_detail', news_id=news.id))
        comment = NewsComment(news=news, user=g.current_user, content=content)
        db.session.add(comment)
        db.session.commit()
        flash('评论已发布', 'success')
        return redirect(url_for('news_detail', news_id=news.id))

    @app.route('/admin/news', methods=['POST'])
    @admin_required
    def create_news():
        title = (request.form.get('title') or '').strip()
        content = (request.form.get('content') or '').strip()
        summary = (request.form.get('summary') or '').strip()
        category = request.form.get('category') or 'campus'
        source = (request.form.get('source') or '').strip()
        is_pinned = bool(request.form.get('is_pinned'))
        if not title or not content:
            flash('标题和内容不能为空', 'error')
            return redirect(url_for('admin'))
        if category not in NEWS_CATEGORY_LABELS:
            category = 'campus'
        if not summary:
            summary = content[:160] + ('…' if len(content) > 160 else '')
        published_at = resolve_publish_time(request.form.get('published_at'))
        news = NewsPost(
            title=title,
            summary=summary,
            content=content,
            category=category,
            source=source,
            is_pinned=is_pinned,
            published_at=published_at,
            created_by=getattr(g, 'current_user', None),
        )
        db.session.add(news)
        db.session.commit()
        flash('资讯已发布', 'success')
        return redirect(url_for('admin', _anchor=f'news{news.id}'))

    @app.route('/admin/news/<int:news_id>/edit', methods=['POST'])
    @admin_required
    def edit_news(news_id: int):
        news = db.session.get(NewsPost, news_id)
        if not news:
            flash('资讯不存在', 'error')
            return redirect(url_for('admin'))
        news.title = (request.form.get('title') or news.title).strip()
        summary = (request.form.get('summary') or '').strip()
        news.summary = summary or news.summary
        content = (request.form.get('content') or '').strip()
        if content:
            news.content = content
        category = request.form.get('category') or news.category
        if category in NEWS_CATEGORY_LABELS:
            news.category = category
        news.source = (request.form.get('source') or '').strip() or None
        news.is_pinned = bool(request.form.get('is_pinned'))
        publish_input = request.form.get('published_at')
        if publish_input:
            news.published_at = resolve_publish_time(publish_input)
        db.session.commit()
        flash('资讯已更新', 'success')
        return redirect(url_for('admin', _anchor=f'news{news.id}'))

    @app.route('/admin/news/<int:news_id>/delete', methods=['POST'])
    @admin_required
    def delete_news(news_id: int):
        news = db.session.get(NewsPost, news_id)
        if not news:
            flash('资讯不存在', 'error')
            return redirect(url_for('admin'))
        db.session.delete(news)
        db.session.commit()
        flash('资讯已删除', 'success')
        return redirect(url_for('admin'))

    @app.route('/catalog')
    @login_required
    def catalog():
        q = request.args.get('q', '').strip()
        page = max(int(request.args.get('page', 1)), 1)
        per_page = 10
        query = Equipment.query
        if q:
            query = query.filter(Equipment.name.ilike(f"%{q}%"))
        total = query.count()
        items = (
            query.order_by(Equipment.name)
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )
        return render_template('catalog.html', equipments=items, q=q, page=page, per_page=per_page, total=total)

    @app.route('/equipment/<int:equipment_id>')
    @login_required
    def equipment_detail(equipment_id: int):
        eq = db.session.get(Equipment, equipment_id)
        if not eq:
            flash('设备未找到', 'error')
            return redirect(url_for('catalog'))
        records = (
            BorrowRecord.query.filter_by(equipment_id=eq.id)
            .order_by(BorrowRecord.borrow_date.desc())
            .limit(50)
            .all()
        )
        return render_template('equipment_detail.html', equipment=eq, records=records)

    @app.route('/add_equipment', methods=['POST'])
    @admin_required
    def add_equipment():
        name = request.form.get('name')
        if not name:
            flash('设备名称不能为空', 'error')
            return redirect(url_for('admin'))
        try:
            total = int(request.form.get('total', 1))
            price = float(request.form.get('price', 0.0))
        except (TypeError, ValueError):
            flash('数值格式不正确', 'error')
            return redirect(url_for('admin'))
        
        image_file = 'default.jpg'
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                import time
                filename = f"{int(time.time())}_{filename}"
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                image_file = filename

        eq = Equipment(name=name, total_quantity=total, available_quantity=total, price=price, image_file=image_file)
        db.session.add(eq)
        db.session.commit()
        flash(f'已添加设备：{name}（总量 {total}，价格 {price}）', 'success')
        return redirect(url_for('admin', added_id=eq.id))

    @app.route('/borrow', methods=['POST'])
    def borrow():
        user = getattr(g, 'current_user', None)
        allow_guest = app.config.get('ALLOW_ANONYMOUS_BORROW', app.config.get('TESTING', False))
        if not user and not allow_guest:
            flash('请先登录后再借用器材', 'error')
            return redirect(url_for('login'))
        try:
            equipment_id = int(request.form.get('equipment_id', 0))
            quantity = int(request.form.get('quantity', 1))
        except (TypeError, ValueError):
            flash('借用请求参数无效', 'error')
            return redirect(request.referrer or url_for('index'))
        user_name = user.username if user else request.form.get('user_name')
        if not user_name:
            flash('请填写借用人姓名', 'error')
            return redirect(request.referrer or url_for('index'))
        try:
            borrow_service.borrow(
                equipment_id=equipment_id,
                quantity=quantity,
                user_name=user_name,
                user=user,
            )
            flash(f'申请已提交，请等待管理员审核。', 'success')
        except BorrowServiceError as exc:
            flash(str(exc), 'error')
        return redirect(request.referrer or (url_for('catalog') if user else url_for('index')))

    @app.route('/register', methods=['GET', 'POST'])
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
            user = User(
                username=username,
                password_hash=pw_hash,
                is_admin=False,
                full_name=request.form.get('full_name'),
                class_name=request.form.get('class_name'),
                gender=request.form.get('gender'),
                phone=request.form.get('phone'),
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('注册并登录成功', 'success')
            return redirect(url_for('catalog'))
        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            admin_pass = os.environ.get('ADMIN_PASS')
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                flash('登录成功', 'success')
                next_url = request.args.get('next') or request.form.get('next')
                if next_url and next_url.startswith('/'):
                    return redirect(next_url)
                return redirect(url_for('catalog'))
            if username == os.environ.get('ADMIN_USER') and admin_pass and password == admin_pass:
                admin_user = User.query.filter_by(username=username).first()
                if not admin_user:
                    admin_user = User(username=username, password_hash=generate_password_hash(password), is_admin=True)
                    db.session.add(admin_user)
                    db.session.commit()
                login_user(admin_user)
                flash('管理员登录成功', 'success')
                return redirect(url_for('admin'))
            flash('用户名或密码错误', 'error')
            return redirect(url_for('login'))
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        logout_user()
        flash('已登出', 'success')
        return redirect(url_for('index'))

    @app.route('/profile')
    @login_required
    def profile():
        user = getattr(g, 'current_user', None)
        borrows_q = BorrowRecord.query.filter_by(user_id=user.id)
        total_borrows = borrows_q.count()
        
        pending = borrows_q.filter_by(status='pending').count()
        approved = borrows_q.filter_by(status='approved').count()
        borrowed = borrows_q.filter(BorrowRecord.status.in_(['borrowed', 'repair_pending'])).count()
        returned = borrows_q.filter_by(status='returned').count()
        
        recent = borrows_q.order_by(BorrowRecord.borrow_date.desc()).limit(50).all()
        
        return render_template('profile.html', user=user, borrows=recent, 
                               total_borrows=total_borrows, 
                               pending=pending, 
                               approved=approved, 
                               borrowed=borrowed,
                               returned=returned)

    @app.route('/profile/edit', methods=['GET', 'POST'])
    @login_required
    def edit_profile():
        user = getattr(g, 'current_user', None)
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
        user = getattr(g, 'current_user', None)
        try:
            record_id = int(request.form.get('record_id', 0))
            is_damaged = bool(request.form.get('is_damaged'))
        except (TypeError, ValueError):
            flash('无效的借用记录', 'error')
            return redirect(request.referrer or url_for('catalog'))
        try:
            result = borrow_service.return_record(record_id=record_id, acting_user=user, is_damaged=is_damaged)
            msg = '归还成功'
            if result.record.fine > 0:
                msg += f'，产生逾期罚款 {result.record.fine} 元'
            if result.record.damage_cost > 0:
                msg += f'，产生损坏赔偿 {result.record.damage_cost} 元'
            flash(msg, 'success')
        except BorrowServiceError as exc:
            flash(str(exc), 'error')
        return redirect(request.referrer or url_for('catalog'))

    @app.route('/api/equipment', methods=['GET'])
    def api_equipment():
        items = [e.to_dict() for e in Equipment.query.order_by(Equipment.name).all()]
        return jsonify(items)

    @app.route('/records')
    @login_required
    def records():
        status = request.args.get('status')
        user = getattr(g, 'current_user', None)
        if user.is_admin:
            query = BorrowRecord.query.join(Equipment)
        else:
            query = BorrowRecord.query.join(Equipment).filter(BorrowRecord.user_id == user.id)
        if status == 'returned':
            query = query.filter(BorrowRecord.return_date.isnot(None))
        elif status == 'outstanding':
            query = query.filter(BorrowRecord.return_date.is_(None))
        items = query.order_by(BorrowRecord.borrow_date.desc()).limit(200).all()
        return render_template('records.html', borrows=items, status=status)

    @app.route('/export_records')
    @admin_required
    def export_records():
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['id', 'equipment', 'user_name', 'quantity', 'borrow_date', 'return_date'])
        for r in BorrowRecord.query.order_by(BorrowRecord.borrow_date.desc()).all():
            cw.writerow([
                r.id,
                r.equipment.name if r.equipment else '',
                r.user_name,
                r.quantity,
                r.borrow_date,
                r.return_date or '',
            ])
        return app.response_class(
            si.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=borrow_records.csv'},
        )

    @app.route('/export_my_records')
    @login_required
    def export_my_records():
        user = getattr(g, 'current_user', None)
        target_user_id = request.args.get('user_id')
        rows = []
        if target_user_id and user.is_admin:
            try:
                target_id = int(target_user_id)
                rows = BorrowRecord.query.filter_by(user_id=target_id).order_by(BorrowRecord.borrow_date.desc()).all()
            except ValueError:
                rows = []
        else:
            rows = BorrowRecord.query.filter_by(user_id=user.id).order_by(BorrowRecord.borrow_date.desc()).all()
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['id', 'equipment', 'user_name', 'quantity', 'borrow_date', 'return_date'])
        for r in rows:
            cw.writerow([
                r.id,
                r.equipment.name if r.equipment else '',
                r.user_name,
                r.quantity,
                r.borrow_date,
                r.return_date or '',
            ])
        return app.response_class(
            si.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=my_borrow_records.csv'},
        )

    @app.route('/admin', methods=['GET', 'POST'])
    def admin():
        from flask import session

        admin_pass = os.environ.get('ADMIN_PASS', 'admin')
        if request.method == 'POST':
            if request.form.get('password') == admin_pass:
                session['is_admin'] = True
                flash('管理员登录成功', 'success')
                return redirect(url_for('admin'))
            flash('密码错误', 'error')
            return redirect(url_for('admin'))
        is_admin = session.get('is_admin', False)
        equipments = []
        users = []
        news_items = []
        pending_records = []
        approved_records = []
        borrowed_records = []
        
        if is_admin:
            equipments = Equipment.query.order_by(Equipment.name).all()
            q = request.args.get('q', '').strip()
            user_query = User.query
            if q:
                user_query = user_query.filter(
                    (User.username.ilike(f"%{q}%"))
                    | (User.full_name.ilike(f"%{q}%"))
                    | (User.class_name.ilike(f"%{q}%"))
                )
            users = user_query.order_by(User.username).all()
            news_items = NewsPost.query.order_by(NewsPost.published_at.desc()).all()
            
            # Fetch records by status
            pending_records = BorrowRecord.query.filter_by(status='pending').order_by(BorrowRecord.borrow_date.desc()).all()
            approved_records = BorrowRecord.query.filter_by(status='approved').order_by(BorrowRecord.borrow_date.desc()).all()
            borrowed_records = BorrowRecord.query.filter(BorrowRecord.status.in_(['borrowed', 'repair_pending'])).order_by(BorrowRecord.borrow_date.desc()).all()

        return render_template('admin.html', is_admin=is_admin, equipments=equipments, users=users, news_items=news_items,
                               pending_records=pending_records, approved_records=approved_records, borrowed_records=borrowed_records)

    @app.route('/admin/user/<int:user_id>')
    @admin_required
    def admin_view_user(user_id: int):
        user = db.session.get(User, user_id)
        if not user:
            flash('用户未找到', 'error')
            return redirect(url_for('admin'))
        records = BorrowRecord.query.filter_by(user_id=user.id).order_by(BorrowRecord.borrow_date.desc()).all()
        return render_template('admin_user.html', user=user, records=records)

    @app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
    @admin_required
    def edit_user(user_id: int):
        user = db.session.get(User, user_id)
        if not user:
            flash('用户未找到', 'error')
            return redirect(url_for('admin'))
        user.full_name = request.form.get('full_name')
        user.class_name = request.form.get('class_name')
        user.gender = request.form.get('gender')
        user.phone = request.form.get('phone')
        db.session.commit()
        flash('用户信息已更新', 'success')
        return redirect(url_for('admin_view_user', user_id=user.id))

    @app.route('/admin/edit_equipment/<int:eq_id>', methods=['POST'])
    @admin_required
    def edit_equipment(eq_id: int):
        eq = db.session.get(Equipment, eq_id)
        if not eq:
            flash('设备未找到', 'error')
            return redirect(url_for('admin'))
        try:
            total = int(request.form.get('total', eq.total_quantity))
            price = float(request.form.get('price', eq.price or 0.0))
        except (ValueError, TypeError):
            total = eq.total_quantity
            price = eq.price
        
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                import time
                filename = f"{int(time.time())}_{filename}"
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                eq.image_file = filename

        diff = total - eq.total_quantity
        eq.total_quantity = total
        eq.available_quantity = max(0, eq.available_quantity + diff)
        eq.price = price
        db.session.commit()
        flash('设备已更新', 'success')
        return redirect(url_for('admin'))

    @app.route('/admin/delete_equipment/<int:eq_id>', methods=['POST'])
    @admin_required
    def delete_equipment(eq_id: int):
        eq = db.session.get(Equipment, eq_id)
        if not eq:
            flash('设备未找到', 'error')
            return redirect(url_for('admin'))
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
        try:
            equipment_id = int(data.get('equipment_id'))
            quantity = int(data.get('quantity', 1))
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid payload'}), 400
        user_name = data.get('user_name')
        if not user_name:
            return jsonify({'error': 'user_name is required'}), 400
        try:
            result = borrow_service.borrow(
                equipment_id=equipment_id,
                quantity=quantity,
                user_name=user_name,
                user=None,
            )
            return jsonify(result.record.to_dict()), 201
        except BorrowServiceError as exc:
            return jsonify({'error': str(exc)}), 400

    @app.route('/api/return', methods=['POST'])
    def api_return():
        data = request.get_json() or {}
        try:
            record_id = int(data.get('record_id'))
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid payload'}), 400
        try:
            result = borrow_service.return_record(record_id=record_id, acting_user=None)
            return jsonify(result.record.to_dict())
        except BorrowServiceError as exc:
            return jsonify({'error': str(exc)}), 400

    @app.route('/admin/approve_borrow/<int:record_id>', methods=['POST'])
    @admin_required
    def admin_approve_borrow(record_id: int):
        try:
            borrow_service.approve_request(record_id=record_id)
            flash('审核通过，请通知学生携带证件领取器材', 'success')
        except BorrowServiceError as exc:
            flash(str(exc), 'error')
        return redirect(request.referrer or url_for('admin'))

    @app.route('/admin/reject_borrow/<int:record_id>', methods=['POST'])
    @admin_required
    def admin_reject_borrow(record_id: int):
        try:
            borrow_service.reject_request(record_id=record_id)
            flash('申请已拒绝', 'success')
        except BorrowServiceError as exc:
            flash(str(exc), 'error')
        return redirect(request.referrer or url_for('admin'))

    @app.route('/admin/confirm_pickup/<int:record_id>', methods=['POST'])
    @admin_required
    def admin_confirm_pickup(record_id: int):
        try:
            borrow_service.confirm_pickup(record_id=record_id)
            flash('确认借出成功', 'success')
        except BorrowServiceError as exc:
            flash(str(exc), 'error')
        return redirect(request.referrer or url_for('admin'))

    @app.route('/report_repair', methods=['POST'])
    @login_required
    def report_repair():
        user = getattr(g, 'current_user', None)
        try:
            record_id = int(request.form.get('record_id', 0))
        except (TypeError, ValueError):
            flash('无效的记录', 'error')
            return redirect(request.referrer or url_for('records'))
        try:
            borrow_service.report_repair(record_id=record_id, acting_user=user)
            flash('报修成功，请将器材归还至体育器材室', 'success')
        except BorrowServiceError as exc:
            flash(str(exc), 'error')
        return redirect(request.referrer or url_for('records'))

    return app


if __name__ == '__main__':
    application = create_app()
    with application.app_context():
        db.create_all()
    application.run(debug=True)
