# Mysite (Flask)

原 Django 项目迁移至 Flask 的 Web 应用，部署在 Vercel（Serverless）。

## 本地开发

```bash
# 方式一：一键守护（自动建 venv、安装依赖、崩溃自动重启）
./start.sh start      # 启动，访问 http://localhost:8000
./start.sh stop       # 停止
./start.sh restart    # 重启
./start.sh status     # 查看运行状态
./start.sh logs       # 跟踪日志

# 方式二：直接用系统 Python
pip install -r requirements.txt
python3 -c "import sys; sys.path.insert(0,'.'); from vercel_app.app import app; app.run(port=8000)"
```

## 部署到 Vercel

```bash
vercel --prod
```

`vercel.json` 已配置：所有路由重写到 `/api/index`（Flask WSGI 入口），函数超时 60s。

### 必须设置的环境变量

在 Vercel 项目 **Settings → Environment Variables** 中添加：

| 变量 | 必填 | 说明 |
|------|------|------|
| `SECRET_KEY` | **必填** | Flask 会话签名密钥，请使用随机长字符串。未设置会回退到不安全的默认值，且会话可被伪造。 |
| `DB_HOST` | **必填** | MySQL 主机地址。 |
| `DB_PORT` | 可选 | MySQL 端口，默认 `3306`。 |
| `DB_NAME` | **必填** | MySQL 数据库名。 |
| `DB_USER` | **必填** | MySQL 用户名。 |
| `DB_PASSWORD` | **必填** | MySQL 密码。 |
| `MIMO_PH` / `MIMO_USER_ID` / `MIMO_SERVICE_TOKEN` | **必填** | 小米 MiMo 聊天凭证（用于 `/mimo-chat-api` 与 OpenAI 兼容接口）。`serviceToken` 会过期，需定期更新。 |
| `NVIDIA_API_KEY` | 可选 | NVIDIA NIM 代理凭证（用于 `/nvidia-chat-api`）。 |

> 所有凭证均通过环境变量注入，代码内不再硬编码任何密钥。完整示例见 `.env.example`。

生成 `SECRET_KEY`：

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## 已知事项

- **静态资源**：`app.py` 的 `static_folder` 指向 `staticfiles/`，该目录需包含模板引用的资源。其中 `staticfiles/apks/app-release.apk`（约 33MB 安装包）为编译产物、未纳入 git，需自行放置到对应路径，否则下载页会 404。
- **AI 流式接口（SSE）**：`/mimo-chat-api`、`/nvidia-chat-api` 在 Vercel Python 函数上的流式表现需上线后实测（可能被平台缓冲）。
- **多轮会话**：OpenAI 兼容接口的会话历史已持久化到 MySQL 表 `chat_conversations`（数据库不可用时退回进程内内存，serverless 多实例下可能丢失）。

## 目录结构

- `api/index.py` — Vercel 入口，导出 Flask `app`（WSGI）
- `vercel_app/` — 应用代码（`views.py` / `script.py` / `app.py` / `sql_db.py`）
- `templates/` — Jinja2 模板
- `start.sh` — 本地守护脚本（start/stop/restart/status/logs + 崩溃自重启）
- `vercel_app/app.py:20` — `_add()` 路由注册辅助
