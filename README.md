# 体育器材借阅系统（示例）

这是一个最小的借阅系统示例，使用 Flask + SQLite。

准备与运行（Windows PowerShell）:

1. 创建并激活虚拟环境：

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
```

2. 安装依赖：

```powershell
pip install -r requirements.txt
```

3. 初始化数据库：

```powershell
python db.py
```

4. 运行应用：

```powershell
python app.py
```

访问 http://127.0.0.1:5000 查看页面。

运行测试：

```powershell
python -m pytest -q
```

说明：这是一个演示级别的实现，适合用于学习与扩展。后续可以添加用户认证、更完善的错误处理与 API 文档。

迁移与安全说明：

-- 已添加 Alembic 基础目录（`alembic/`）用于未来的数据库迁移管理。当前仓库包含一个基线空迁移 `alembic/versions/0001_initial.py`，可作为起点。

使用 Alembic（推荐）
1. 备份现有数据库（非常重要）：

```powershell
copy .\app.db .\app.db.bak
```

2. 安装依赖（虚拟环境建议）：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

3. 生成自动迁移（会对比模型和 DB）：

```powershell
alembic revision --autogenerate -m "describe changes"
```

4. 在本地先 review 生成的迁移脚本（`alembic/versions/`），确认无误后应用迁移：

```powershell
alembic upgrade head
```

说明：如果你的 DB 是已有生产数据，请务必先备份（上面演示），并在测试环境中先运行迁移以确认没有破坏性变化。

CSRF 与测试
- 项目已集成 CSRF 保护：若安装 `Flask-WTF` 则使用其 `CSRFProtect`，否则仓库包含一个基于 session 的轻量回退实现来保持表单保护。
- 可运行示例 smoke 测试（在虚拟环境中运行）：

```powershell
python .\scripts\csrf_smoke.py
```

或将其转换为 pytest 用例并运行：

```powershell
python -m pytest -q
```

生产注意事项：
- 请将 `FLASK_SECRET`（或 `app.config['SECRET_KEY']`）在生产中设置为安全随机值。
- 在 TLS/HTTPS 下启用 `FORCE_SECURE_COOKIES=1` 环境变量以强制 `SESSION_COOKIE_SECURE=True`。
