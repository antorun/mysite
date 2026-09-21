# 项目长期记忆 (mysite / vercel_app)

## 部署架构（重要）
- 开发/验证在本地 Mac：`127.0.0.1:8000`（用 `./start.sh` 或 `python -c "...app.run(port=8000)"` 后台常驻）。
- 对外暴露入口在服务器 `38.76.220.68:8000`（用户外部客户端/代理平台填的 API Base URL 指向它）。
- **改完本地代码后，必须同步最新代码到 38.76.220.68 并重启 8000 服务 + 放行防火墙，外部调用才会生效**。仅本地重启无法解决外部 503。
- 外部调用经某代理网关转发到 `38.76.220.68:8000`；若服务器 8000 无监听，网关返回 `custom-model-503`（与 API Key 无关，本端点不校验 key）。

## 技术约定
- MiMo 端点不校验 Authorization，任意 key（如 `sk-xxx`）均可。
- Flask 已开 `TEMPLATES_AUTO_RELOAD=True`，改 HTML 模板即时生效无需重启。
- 路由：`/mimo-chat/`（页面）、`/mimo-chat-api`（自定义 SSE）、`/v1/chat/completions`（OpenAI 兼容，流式+非流式）。
- 服务器系统 CentOS Stream 9，防火墙 `firewall-cmd`；数据库 PostgreSQL/MySQL 凭证 root/Zhl127210342。
