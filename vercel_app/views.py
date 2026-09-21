import json
import time
import uuid
import re
import os
import hmac
import secrets
import hashlib
import base64
import threading
import functools
import traceback
from datetime import datetime
import requests
from flask import (
    request, session, render_template, redirect,
    make_response, Response, stream_with_context,
)
from . import sql_db, mimo


# ---- 登录认证 ----
SESSION_KEY = 'auth_user'
_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'


_PBKDF2_ITERATIONS = 120_000


def hash_password(password: str) -> str:
    """生成加盐 PBKDF2-SHA256 哈希（格式: pbkdf2_sha256$iter$salt$digest）"""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    ).hex()
    return f'pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${digest}'


def verify_password(stored: str, password: str) -> bool:
    """校验密码；兼容迁移前的未加盐 SHA-256 格式，便于存量用户平滑过渡。"""
    if not stored:
        return False
    if stored.startswith('pbkdf2_sha256$'):
        try:
            _, iters, salt, digest = stored.split('$')
            calc = hashlib.pbkdf2_hmac(
                'sha256', password.encode(), bytes.fromhex(salt), int(iters)
            ).hex()
            return hmac.compare_digest(calc, digest)
        except Exception:
            return False
    return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored)


def check_auth() -> bool:
    """检查用户是否已登录"""
    return session.get(SESSION_KEY) is not None


def login_required(view_func):
    """装饰器：需要登录才能访问"""
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        if not check_auth():
            return redirect('/login/')
        return view_func(*args, **kwargs)
    return wrapper


def login_page():
    """登录页面"""
    if check_auth():
        return redirect('/main/')
    return render_template('pages/login.html')


def login_api():
    """登录 API"""
    if request.method == 'OPTIONS':
        return _cors_preflight()
    if request.method != 'POST':
        return _json_response({'status': 'error', 'message': '请使用 POST 请求'})
    try:
        body = json.loads(request.get_data().decode('utf-8'))
        username = body.get('username', '').strip()
        password = body.get('password', '')
    except Exception:
        return _json_response({'status': 'error', 'message': '请求数据格式错误'})
    if not username or not password:
        return _json_response({'status': 'error', 'message': '用户名和密码不能为空'})
    try:
        with sql_db.DatabaseManager() as db:
            row = db.query_one('users', '"username" = %s', (username,))
            if row and verify_password(row[2], password):
                session[SESSION_KEY] = username
                # 旧的无盐 SHA-256 哈希在登录成功后自动升级为加盐 PBKDF2
                if not row[2].startswith('pbkdf2_sha256$'):
                    db.update('users', {'password': hash_password(password)}, '"username" = %s', (username,))
                return _json_response({'status': 'ok', 'message': '登录成功'})
        return _json_response({'status': 'error', 'message': '用户名或密码错误'})
    except Exception as e:
        traceback.print_exc()
        return _json_response({'status': 'error', 'message': sql_db.friendly_db_error(e)})


def logout_view():
    """登出"""
    session.clear()
    return redirect('/login/')


def change_password_api():
    """修改密码 API"""
    if request.method != 'POST':
        return _json_response({'status': 'error', 'message': '请使用 POST 请求'})
    try:
        body = json.loads(request.get_data().decode('utf-8'))
        username = body.get('username', '').strip()
        old_password = body.get('oldPassword', '')
        new_password = body.get('newPassword', '')
    except Exception:
        return _json_response({'status': 'error', 'message': '请求数据格式错误'})
    if not username or not old_password or not new_password:
        return _json_response({'status': 'error', 'message': '用户名和密码不能为空'})
    if len(new_password) < 4:
        return _json_response({'status': 'error', 'message': '新密码至少 4 位'})
    try:
        with sql_db.DatabaseManager() as db:
            row = db.query_one('users', '"username" = %s', (username,))
            if not row:
                return _json_response({'status': 'error', 'message': '用户不存在'})
            if not verify_password(row[2], old_password):
                return _json_response({'status': 'error', 'message': '原密码错误'})
            db.update('users', {'password': hash_password(new_password)}, '"username" = %s', (username,))
            return _json_response({'status': 'ok', 'message': '密码修改成功'})
    except Exception as e:
        return _json_response({'status': 'error', 'message': sql_db.friendly_db_error(e)})


# ===== 登录认证结束 =====


# ===== 人员管理 API =====

@login_required
def users_manage_page():
    """人员管理页面（仅管理员可访问）"""
    username = session.get(SESSION_KEY, '')
    if get_user_role(username) != 'admin':
        return redirect('/')
    return render_template('pages/users_manage.html', username=username)


def admin_required(view_func):
    """装饰器：需要管理员权限"""
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        if not check_auth():
            return _json_response({'status': 'error', 'message': '请先登录'})
        username = session.get(SESSION_KEY, '')
        if get_user_role(username) != 'admin':
            return _json_response({'status': 'error', 'message': '无权限'})
        return view_func(*args, **kwargs)
    return wrapper


@admin_required
def users_list_api():
    """获取所有用户列表"""
    if request.method == 'OPTIONS':
        return _cors_preflight()
    try:
        with sql_db.DatabaseManager() as db:
            users = [{'id': r[0], 'username': r[1],
                      'role': r[4] if len(r) > 4 else 'user',
                      'created_at': str(r[3]) if len(r) > 3 and r[3] else ''}
                     for r in db.query_all('users')]
        return _json_response({'status': 'ok', 'users': users})
    except Exception as e:
        return _json_response({'status': 'error', 'message': str(e)})


def register_api():
    """公开注册接口（无需登录）"""
    if request.method != 'POST':
        return _json_response({'status': 'error', 'message': '请使用 POST 请求'})
    try:
        body = json.loads(request.get_data().decode('utf-8'))
        username = body.get('username', '').strip()
        password = body.get('password', '')
        confirm = body.get('confirmPassword', '')
    except Exception:
        return _json_response({'status': 'error', 'message': '请求数据格式错误'})
    if not username or not password:
        return _json_response({'status': 'error', 'message': '用户名和密码不能为空'})
    if ' ' in username or len(username) < 3 or len(username) > 20:
        return _json_response({'status': 'error', 'message': '用户名需 3-20 位且不含空格'})
    if len(password) < 4:
        return _json_response({'status': 'error', 'message': '密码至少 4 位'})
    if password != confirm:
        return _json_response({'status': 'error', 'message': '两次输入的密码不一致'})
    try:
        with sql_db.DatabaseManager() as db:
            if db.query_one('users', '"username" = %s', (username,)):
                return _json_response({'status': 'error', 'message': '用户名已存在'})
            db.add_columns('users', ['username', 'password', 'role', 'created_at'])
            # 首个注册用户自动成为管理员，其余为普通用户
            is_first = not db.query_all('users')
            db.insert('users', {
                'username': {'values': username},
                'password': {'values': hash_password(password)},
                'role': {'values': 'admin' if is_first else 'user'},
                'created_at': {'values': str(datetime.now())},
            })
        return _json_response({'status': 'ok', 'message': '注册成功，请登录'})
    except Exception as e:
        return _json_response({'status': 'error', 'message': sql_db.friendly_db_error(e)})


@admin_required
def users_add_api():
    """新增用户"""
    if request.method == 'OPTIONS':
        return _cors_preflight("POST, OPTIONS")
    if request.method != 'POST':
        return _json_response({'status': 'error', 'message': '请使用 POST 请求'})
    try:
        body = json.loads(request.get_data().decode('utf-8'))
        username = body.get('username', '').strip()
        password = body.get('password', '').strip()
        role = body.get('role', 'user').strip()
    except Exception:
        return _json_response({'status': 'error', 'message': '请求数据格式错误'})
    if not username or not password:
        return _json_response({'status': 'error', 'message': '用户名和密码不能为空'})
    if len(password) < 4:
        return _json_response({'status': 'error', 'message': '密码至少 4 位'})
    if role not in ('admin', 'user'):
        return _json_response({'status': 'error', 'message': '角色无效'})
    try:
        with sql_db.DatabaseManager() as db:
            if db.query_one('users', '"username" = %s', (username,)):
                return _json_response({'status': 'error', 'message': '用户名已存在'})
            db.add_columns('users', ['username', 'password', 'role', 'created_at'])
            db.insert('users', {
                'id': {'values': str(int(time.time() * 1000000))},
                'username': {'values': username},
                'password': {'values': hash_password(password)},
                'role': {'values': role},
                'created_at': {'values': str(datetime.now())},
            })
        return _json_response({'status': 'ok', 'message': '用户添加成功'})
    except Exception as e:
        return _json_response({'status': 'error', 'message': str(e)})


@admin_required
def users_edit_api():
    """编辑用户"""
    if request.method == 'OPTIONS':
        return _cors_preflight("POST, OPTIONS")
    if request.method != 'POST':
        return _json_response({'status': 'error', 'message': '请使用 POST 请求'})
    try:
        body = json.loads(request.get_data().decode('utf-8'))
        user_id = body.get('id')
        new_password = body.get('password', '').strip()
        new_role = body.get('role', '').strip()
    except Exception:
        return _json_response({'status': 'error', 'message': '请求数据格式错误'})
    if not user_id:
        return _json_response({'status': 'error', 'message': '缺少用户 ID'})
    if new_role and new_role not in ('admin', 'user'):
        return _json_response({'status': 'error', 'message': '角色无效'})
    if new_password and len(new_password) < 4:
        return _json_response({'status': 'error', 'message': '新密码至少 4 位'})
    if not new_password and not new_role:
        return _json_response({'status': 'error', 'message': '没有需要修改的内容'})
    try:
        with sql_db.DatabaseManager() as db:
            update_data = {}
            if new_password:
                update_data['password'] = hash_password(new_password)
            if new_role:
                update_data['role'] = new_role
            db.update('users', update_data, '"id" = %s', (str(user_id),))
        return _json_response({'status': 'ok', 'message': '修改成功'})
    except Exception as e:
        return _json_response({'status': 'error', 'message': str(e)})


@admin_required
def users_delete_api():
    """删除用户"""
    if request.method == 'OPTIONS':
        return _cors_preflight("POST, OPTIONS")
    if request.method != 'POST':
        return _json_response({'status': 'error', 'message': '请使用 POST 请求'})
    try:
        body = json.loads(request.get_data().decode('utf-8'))
        user_id = body.get('id')
    except Exception:
        return _json_response({'status': 'error', 'message': '请求数据格式错误'})
    if not user_id:
        return _json_response({'status': 'error', 'message': '缺少用户 ID'})
    try:
        with sql_db.DatabaseManager() as db:
            username = session.get(SESSION_KEY, '')
            if db.query_one('users', '"id" = %s AND "username" = %s', (str(user_id), username)):
                return _json_response({'status': 'error', 'message': '不能删除自己'})
            db.delete('users', '"id" = %s', (str(user_id),))
        return _json_response({'status': 'ok', 'message': '删除成功'})
    except Exception as e:
        return _json_response({'status': 'error', 'message': str(e)})


# ===== 人员管理结束 =====


def _json_response(data, status=200):
    resp = make_response(json.dumps(data, ensure_ascii=False), status)
    resp.headers['Content-Type'] = 'application/json;charset=UTF-8'
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


def _cors_preflight(methods="GET, POST, OPTIONS"):
    resp = make_response('')
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = methods
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp


# 表名白名单校验：所有接受表名的接口都先过这一关，杜绝 SQL 注入
_TABLE_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')


def _safe_table(name: str) -> bool:
    return bool(_TABLE_RE.match(name or ''))


def get_vmess():
    try:
        t = requests.get('https://raw.githubusercontent.com/mksshare/mksshare.github.io/main/README.md', timeout=10).text
        return Response(base64.b64encode(t.split('```')[1].split('```')[0].encode()).decode(), mimetype='text/plain')
    except Exception:
        return Response('', mimetype='text/plain')


def map_info():
    try:
        r = requests.get(
            'https://screeps.com/api/game/room-terrain?encoded=true&room=W59S33&shard=shard3',
            headers={'User-Agent': _UA}, timeout=10)
        return _json_response(r.json())
    except Exception as e:
        return _json_response({'error': str(e)})


_SUBSCRIBE_SOURCES = {
    '1': 'https://u0eMJo.absslk.xyz/04912563f620c0b6e2eaae5c3b6d9bf5',
    '2': 'https://raw.githubusercontent.com/abshare/abshare.github.io/main/README.md',
    '3': 'https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/v2ray.txt',
    '4': 'https://raw.githubusercontent.com/ZywChannel/free/main/sub',
    '5': 'https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt',
    '6': 'https://raw.githubusercontent.com/Huibq/TrojanLinks/master/links/vmess',
    '7': 'https://raw.githubusercontent.com/Huibq/TrojanLinks/master/links/temporary',
    '8': 'https://proxy.v2gh.com/https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub',
}


def subscribe():
    url = _SUBSCRIBE_SOURCES.get(request.args.get('subtype', ''))
    if not url:
        return Response('', mimetype='text/plain')
    try:
        t = requests.get(url, timeout=15).text
        if request.args.get('subtype') == '2':
            return Response(base64.b64encode(t.split('```')[1].split('``')[0].encode()).decode(), mimetype='text/plain')
        return Response(t, mimetype='text/plain')
    except Exception:
        return Response('', mimetype='text/plain')


def _render_page(template, content_type=None):
    """闭包生成简单页面视图"""
    def view():
        if content_type:
            return make_response(render_template(template), 200, {'Content-Type': content_type})
        return render_template(template)
    return view

# 简单页面视图
scum9996 = _render_page('servers/9996.html')
crosshairsetting = _render_page('tools/config.html')
crosshair = _render_page('tools/crosshair.html')
player = _render_page('tools/player.html')
M3U8_player = _render_page('tools/M3U8_player.html')
verfy = _render_page('verfy.txt', 'text/plain')
verfy2 = _render_page('5C2C670E8B1EF1276D3D7821DC3154EF.txt', 'text/plain')

def get_user_role(username: str) -> str:
    """从数据库获取用户角色（serverless 无状态环境，每次直查库，避免缓存不一致）"""
    if not username:
        return 'user'
    try:
        with sql_db.DatabaseManager() as db:
            row = db.query_one('users', '"username" = %s', (username,))
            if row:
                return row[4] if len(row) > 4 else 'user'
    except Exception:
        pass
    return 'user'


@login_required
def main():
    username = session.get(SESSION_KEY, '')
    role = get_user_role(username)
    return render_template('pages/main.html', username=username, role=role)


@login_required
def dashboard_home():
    """后台管理仪表盘首页（iframe 内嵌欢迎页）"""
    username = session.get(SESSION_KEY, '')
    role = get_user_role(username)
    return render_template('pages/dashboard_home.html', username=username, role=role)


def reward():
    return render_template('pages/reward.html')


def sw_proxy_js():
    """Serve Service Worker proxy script"""
    resp = make_response(render_template('pages/sw-proxy.js'))
    resp.headers['Content-Type'] = 'application/javascript'
    resp.headers['Service-Worker-Allowed'] = '/'
    return resp


def reward_proxy():
    """代理转发 reward_video 请求"""
    if request.method == 'OPTIONS':
        return _cors_preflight("POST, OPTIONS")
    target = 'https://api-access.pangolin-sdk-toutiao.com/api/ad/union/mediation/reward_video/reward/'
    headers = {
        'user-agent': 'Dalvik/2.1.0 (Linux; U; Android 14; zh-CN; SM-S9420 Build/UQ1A.240205.05262019)',
        'x-pglcypher': request.headers.get('X-PGLCYPHER', '4'),
        'content-type': request.content_type or 'application/octet-stream',
        'accept-encoding': 'gzip',
    }
    try:
        resp = requests.post(target, data=request.get_data(), headers=headers, timeout=8)
        response = make_response(resp.content, resp.status_code)
        response.headers['Content-Type'] = resp.headers.get('Content-Type', 'application/octet-stream')
        for h in ('Content-Encoding', 'Content-Length', 'X-Server-Info'):
            if h in resp.headers:
                response.headers[h] = resp.headers[h]
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    except requests.exceptions.Timeout:
        return _json_response({'error': 'Proxy timeout (>8s)', 'type': 'timeout'}, 504)
    except requests.exceptions.RequestException as e:
        return _json_response({'error': str(e)[:500], 'type': 'request'}, 502)
    except Exception as e:
        return _json_response({'error': str(e)[:500], 'type': 'unknown'}, 500)


def ai_chat():
    return render_template('pages/ai_chat.html')


def ai_chat_api():
    """聊天数据同步 API"""
    if request.method == 'OPTIONS':
        return _cors_preflight()
    if request.method == 'GET':
        with sql_db.DatabaseManager() as db:
            db.add_columns('ai_chat_data', ['data'])
            rows = db.query_all('ai_chat_data')
            if rows and len(rows[-1]) > 0:
                data_str = rows[-1][-1]
                if data_str:
                    return _json_response(json.loads(data_str))
        return _json_response({})
    elif request.method == 'POST':
        body = json.loads(request.get_data().decode('utf-8'))
        with sql_db.DatabaseManager() as db:
            db.add_columns('ai_chat_data', ['data'])
            db.delete('ai_chat_data', '1=1')
            db.insert('ai_chat_data', {'data': {'values': json.dumps(body, ensure_ascii=False)}})
        return _json_response({'status': 'ok', 'message': '数据已同步到数据库'})
    return _json_response({'status': 'error', 'message': '不支持的请求方法'})


device = _render_page('pages/device.html')
controller = _render_page('tools/c.html')
glm_chat = _render_page('pages/glm_chat.html')
nvidia_chat = _render_page('pages/nvidia_chat.html')
mimo_chat = _render_page('pages/mimo_chat.html')


# ===== 小米 MiMo 流式聊天接口 =====
def mimo_chat_api():
    """小米 MiMo 聊天流式接口（SSE）。

    请求体 (POST JSON):
        query            (str, 必填) 用户问题
        conversation_id  (str, 可选) 会话 ID，不传则自动新建
        msg_id           (str, 可选) 消息 ID，不传则自动生成
        enable_thinking  (bool, 可选) 是否开启深度思考，默认 False

    响应: text/event-stream，按 SSE 逐块推送：
        data: {"content": "增量文本"}\n\n
        data: [DONE]\n\n   # 结束标记
        data: {"error": "错误信息"}   # 出错时
    """
    if request.method != 'POST':
        return _json_response({'error': '仅支持POST请求'}, 405)
    try:
        body = json.loads(request.get_data().decode('utf-8'))
    except Exception:
        return _json_response({'error': '请求体格式错误'}, 400)

    query = (body.get('query') or '').strip()
    if not query:
        return _json_response({'error': 'query 不能为空'}, 400)
    conversation_id = (body.get('conversation_id') or '').strip()
    msg_id = (body.get('msg_id') or '').strip()
    enable_thinking = bool(body.get('enable_thinking', False))

    def sse_gen():
        try:
            for kind, text in mimo.stream_chat(
                query,
                conversation_id=conversation_id,
                msg_id=msg_id,
                enable_thinking=enable_thinking,
            ):
                key = 'reasoning' if kind == 'reasoning' else 'content'
                payload = json.dumps({key: text}, ensure_ascii=False)
                yield f'data: {payload}\n\n'
            yield 'data: [DONE]\n\n'
        except requests.exceptions.Timeout:
            err = json.dumps({'error': '请求 MiMo 超时'}, ensure_ascii=False)
            yield f'data: {err}\n\n'
        except requests.exceptions.HTTPError as e:
            err = json.dumps({'error': f'MiMo 返回错误: {e}'}, ensure_ascii=False)
            yield f'data: {err}\n\n'
        except Exception as e:
            err = json.dumps({'error': str(e)[:500]}, ensure_ascii=False)
            yield f'data: {err}\n\n'

    response = Response(stream_with_context(sse_gen()), content_type='text/event-stream', status=200)
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['X-Conversation-Id'] = conversation_id
    return response


# ===== OpenAI 兼容接口（/v1/chat/completions，后端转发到小米 MiMo） =====
def _openai_text(content):
    """从 OpenAI content 字段抽取纯文本（兼容字符串或 [{'type':'text','text':...}] 多模态格式）"""
    if isinstance(content, list):
        return ''.join(p.get('text', '') for p in content if isinstance(p, dict))
    return content if isinstance(content, str) else ''


# 多轮会话上下文：服务端维护，保证第三方 OpenAI 客户端也能"联想"（记住上文）。
# 优先持久化到 MySQL（Vercel serverless 无状态、多实例，进程内内存不可靠）；
# 数据库不可用时退回进程内内存，保证聊天功能不中断。
_CONV_LOCK = threading.Lock()
_CONVERSATIONS = {}  # 内存降级兜底: conv_id -> [{'role':..., 'content':...}, ...]
_MAX_HISTORY = 100   # 单会话保留的最大消息数，防止无限增长
_CONV_TABLE = 'chat_conversations'


def _same_msg(a, b):
    """比较两条消息是否相同（按 role + content 文本）"""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    return a.get('role') == b.get('role') and _openai_text(a.get('content', '')) == _openai_text(b.get('content', ''))


def _is_prefix(prefix, full):
    """判断 prefix 是否为 full 的前缀（逐条比较）"""
    if len(prefix) > len(full):
        return False
    return all(_same_msg(prefix[i], full[i]) for i in range(len(prefix)))


def _merge_conversation(conv_id, messages):
    """合并服务端历史与本次 messages，返回完整对话。

    策略（兼容两类客户端）：
    - 若已存历史是本次 messages 的前缀 → 说明客户端每轮都发"完整历史"，
      直接以本次 messages 为准（避免重复累积）。
    - 否则 → 视为"只发最新一条、靠 conv_id 让服务端记忆前情"，追加到已存历史之后。
    - 客户端未提供 conversation_id：以本次 messages 作为上下文，并生成 conv_id 供后续复用。
    """
    norm = [{'role': m.get('role', 'user'), 'content': _openai_text(m.get('content', ''))}
            for m in messages if isinstance(m, dict)]
    hist = _load_conversation(conv_id)
    if hist is None:
        hist = _CONVERSATIONS.get(conv_id) or []
    if _is_prefix(hist, norm):
        hist = list(norm)          # 客户端发了完整/扩展历史
    else:
        hist = hist + norm         # 客户端只发新增部分，服务端续接
    if len(hist) > _MAX_HISTORY:
        hist = hist[-_MAX_HISTORY:]
    _store_conversation(conv_id, hist)
    return list(hist)


def _load_conversation(conv_id):
    """从 MySQL 读取会话历史；未命中或数据库不可用时返回 None。"""
    try:
        with sql_db.DatabaseManager() as db:
            db.add_columns(_CONV_TABLE, ['conv_id', 'messages', 'updated_at'])
            row = db.query_one(_CONV_TABLE, '"conv_id" = %s', (conv_id,))
            if row and len(row) > 1 and row[1]:
                return json.loads(row[1])
    except Exception:
        pass
    return None


def _store_conversation(conv_id, hist):
    """持久化会话历史：优先写 MySQL，失败退回进程内内存。"""
    try:
        with sql_db.DatabaseManager() as db:
            db.add_columns(_CONV_TABLE, ['conv_id', 'messages', 'updated_at'])
            payload = json.dumps(hist, ensure_ascii=False)
            updated_at = str(datetime.now())
            if db.query_one(_CONV_TABLE, '"conv_id" = %s', (conv_id,)):
                db.update(_CONV_TABLE, {'messages': payload, 'updated_at': updated_at},
                          '"conv_id" = %s', (conv_id,))
            else:
                db.insert(_CONV_TABLE, {
                    'conv_id': {'values': conv_id},
                    'messages': {'values': payload},
                    'updated_at': {'values': updated_at},
                })
            return
    except Exception:
        pass
    with _CONV_LOCK:
        _CONVERSATIONS[conv_id] = hist


def _append_assistant(conv_id, text):
    """将本轮 assistant 回复写回服务端历史，保证下一轮能'联想'到自己的上文。"""
    if not conv_id or not text:
        return
    hist = _load_conversation(conv_id)
    if hist is None:
        hist = _CONVERSATIONS.get(conv_id)
    if hist is None:
        return
    hist = list(hist)
    hist.append({'role': 'assistant', 'content': text})
    if len(hist) > _MAX_HISTORY:
        hist = hist[-_MAX_HISTORY:]
    _store_conversation(conv_id, hist)


def _format_transcript(messages):
    """将完整对话拼成 MiMo 可理解的纯文本 prompt"""
    return '\n'.join(f"{m['role']}: {m['content']}" for m in messages).strip()


def openai_chat_completions():
    """OpenAI 兼容的 /v1/chat/completions 接口，后端转发到小米 MiMo。

    请求体（兼容 OpenAI）:
        model            (str)  模型名（原样回显，实际调用 mimo-v2.5-pro）
        messages         (list) 对话历史 [{role, content}, ...]，必填
        stream           (bool) 是否 SSE 流式，默认 false
        temperature/top_p/max_tokens  兼容字段（MiMo 暂未使用）
        enable_thinking  (bool) 自定义扩展：是否回传思考过程，默认 false
        conversation_id  (str)  可选；或经 X-Conversation-Id 头传入，实现有状态多轮

    响应:
        stream=true  -> SSE 增量（object=chat.completion.chunk），含 reasoning_content
        stream=false -> 完整 JSON（object=chat.completion）
    """
    if request.method == 'OPTIONS':
        return _cors_preflight("POST, OPTIONS")
    if request.method != 'POST':
        return _json_response(
            {'error': {'message': '仅支持POST请求', 'type': 'invalid_request_error'}}, 405)

    try:
        body = json.loads(request.get_data().decode('utf-8'))
    except Exception:
        return _json_response(
            {'error': {'message': '请求体格式错误', 'type': 'invalid_request_error'}}, 400)

    messages = body.get('messages') or []
    if not isinstance(messages, list) or not messages:
        return _json_response(
            {'error': {'message': 'messages 不能为空', 'type': 'invalid_request_error'}}, 400)

    model = body.get('model') or 'mimo-v2.5-pro'
    stream = bool(body.get('stream', False))
    enable_thinking = bool(body.get('enable_thinking', body.get('thinking', False)))
    conversation_id = (body.get('conversation_id') or request.headers.get('X-Conversation-Id') or '').strip()
    if not conversation_id:
        conversation_id = 'conv-' + uuid.uuid4().hex

    # 合并服务端历史，得到完整上下文（客户端只发最新一条并复用 conv_id 时也能"联想"）
    history = _merge_conversation(conversation_id, messages)
    query = _format_transcript(history)
    if not query:
        return _json_response(
            {'error': {'message': '未找到有效的用户消息', 'type': 'invalid_request_error'}}, 400)

    # 每次调用给 MiMo 一个新的 conversationId，避免 MiMo 侧累积重复上下文
    mimo_cid = uuid.uuid4().hex

    cid = 'chatcmpl-' + uuid.uuid4().hex
    created = int(time.time())

    # ---- 非流式：积攒完整回复 ----
    if not stream:
        full = ''
        try:
            for kind, text in mimo.stream_chat(
                query, conversation_id=mimo_cid, enable_thinking=enable_thinking
            ):
                if kind == 'content':
                    full += text
        except requests.exceptions.Timeout:
            return _json_response({'error': {'message': '请求 MiMo 超时', 'type': 'api_error'}}, 504)
        except Exception as e:
            return _json_response({'error': {'message': f'MiMo 调用失败: {e}', 'type': 'api_error'}}, 502)
        _append_assistant(conversation_id, full)
        resp = _json_response({
            'id': cid, 'object': 'chat.completion', 'created': created, 'model': model,
            'choices': [{
                'index': 0,
                'message': {'role': 'assistant', 'content': full},
                'finish_reason': 'stop',
            }],
            'usage': {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0},
        })
        resp.headers['X-Conversation-Id'] = conversation_id
        return resp

    # ---- 流式：OpenAI chunk SSE ----
    def sse_gen():
        # 首块：声明 assistant 角色
        first = {
            'id': cid, 'object': 'chat.completion.chunk', 'created': created, 'model': model,
            'choices': [{'index': 0, 'delta': {'role': 'assistant'}, 'finish_reason': None}],
        }
        yield 'data: ' + json.dumps(first, ensure_ascii=False) + '\n\n'
        full = ''
        try:
            for kind, text in mimo.stream_chat(
                query, conversation_id=mimo_cid, enable_thinking=enable_thinking
            ):
                if kind == 'content':
                    full += text
                delta = {'reasoning_content': text} if kind == 'reasoning' else {'content': text}
                chunk = {
                    'id': cid, 'object': 'chat.completion.chunk', 'created': created, 'model': model,
                    'choices': [{'index': 0, 'delta': delta, 'finish_reason': None}],
                }
                yield 'data: ' + json.dumps(chunk, ensure_ascii=False) + '\n\n'
            _append_assistant(conversation_id, full)
            end = {
                'id': cid, 'object': 'chat.completion.chunk', 'created': created, 'model': model,
                'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}],
            }
            yield 'data: ' + json.dumps(end, ensure_ascii=False) + '\n\n'
        except Exception as e:
            err = {
                'id': cid, 'object': 'chat.completion.chunk', 'created': created, 'model': model,
                'choices': [{'index': 0, 'delta': {'content': f'[错误] {e}'}, 'finish_reason': 'stop'}],
            }
            yield 'data: ' + json.dumps(err, ensure_ascii=False) + '\n\n'
        yield 'data: [DONE]\n\n'

    response = Response(stream_with_context(sse_gen()), content_type='text/event-stream', status=200)
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['X-Conversation-Id'] = conversation_id
    return response

# ===== 公开展示页面（无需登录） =====
home_page = _render_page('pages/home.html')
download_page = _render_page('pages/download.html')
user_agreement = _render_page('pages/user_agreement.html')
about_page = _render_page('pages/about.html')


def _nvidia_chat_username():
    """获取当前用户的唯一标识"""
    return session.get(SESSION_KEY) or 'anonymous'


def nvidia_chat_sync_api():
    """NVIDIA 聊天记录同步 API"""
    if request.method == 'OPTIONS':
        return _cors_preflight()
    username = _nvidia_chat_username()
    if request.method == 'GET':
        with sql_db.DatabaseManager() as db:
            db.add_columns('nvidia_chat_data', ['username', 'data', 'model', 'updated_at'])
            rows = db.query_where('nvidia_chat_data', '"username" = %s', (username,))
            if rows:
                row = rows[-1]
                try:
                    return _json_response({
                        'messages': json.loads(row[2]) if len(row) > 2 and row[2] else [],
                        'model': row[3] if len(row) > 3 else '',
                    })
                except Exception:
                    return _json_response({'messages': [], 'model': ''})
        return _json_response({'messages': [], 'model': ''})
    elif request.method == 'POST':
        try:
            body = json.loads(request.get_data().decode('utf-8'))
        except Exception:
            return _json_response({'error': '请求体格式错误'}, 400)
        messages = body.get('messages', [])
        model = body.get('model', '')
        with sql_db.DatabaseManager() as db:
            db.add_columns('nvidia_chat_data', ['username', 'data', 'model', 'updated_at'])
            db.delete('nvidia_chat_data', '"username" = %s', (username,))
            db.insert('nvidia_chat_data', {
                'username': {'values': username},
                'data': {'values': json.dumps(messages, ensure_ascii=False)},
                'model': {'values': model},
                'updated_at': {'values': str(datetime.now())},
            })
        return _json_response({'status': 'ok'})
    return _json_response({'status': 'error', 'message': '不支持的请求方法'})


server_search = servers = _render_page('servers/server_search.html')


def server_info():
    return render_template('servers/server_info.html', server_id=request.args.get('id'))


def _find_audio_urls(obj):
    """Recursively search for audio URLs and titles in a JSON-like structure."""
    import re

    urls = []

    audio_ext_re = re.compile(r"https?://[^\s'\"<>]+\.(?:mp3|m4a|aac|wav|ogg|flac)", re.IGNORECASE)
    generic_url_re = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)

    def walk(o, title_hint=None):
        if isinstance(o, dict):
            # try to get a title-like hint
            t = o.get('title') or o.get('name') or o.get('titleName') or title_hint
            for _, v in o.items():
                if isinstance(v, (dict, list)):
                    walk(v, t)
                elif isinstance(v, str):
                    # first look for explicit audio extensions
                    for m in audio_ext_re.findall(v):
                        urls.append({'title': t or o.get('nickname') or o.get('label') or '', 'url': m})
                    # fallback: any url that contains typical audio host keywords
                    if 'xmcdn' in v or 'play' in v or 'audio' in v:
                        for m in generic_url_re.findall(v):
                            urls.append({'title': t or '', 'url': m})
        elif isinstance(o, list):
            for i in o:
                walk(i, title_hint)

    walk(obj)
    # deduplicate by url preserving first title
    seen = set()
    out = []
    for it in urls:
        if it['url'] not in seen:
            seen.add(it['url'])
            out.append(it)
    return out


def radio():
    """Fetch Ximalaya radio search API and render a page with playable audio links."""
    url = 'https://m.ximalaya.com/radio-first-page-app/search?locationId=0&locationTypeId=0&pageNum=0&pageSize=300&categoryId=0'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
    }
    try:
        r = requests.get(url, headers=headers, timeout=10)
    except Exception as e:
        return make_response(f'Error fetching remote API: {e}')

    items = []
    raw = None
    try:
        raw = r.json()
        items = _find_audio_urls(raw)
    except Exception:
        # not JSON or parse failed — try to extract URLs from plain text
        import re
        text = r.text
        raw = text
        audio_ext_re = re.compile(r"https?://[^\s'\"<>]+\.(?:mp3|m4a|aac|wav|ogg|flac)", re.IGNORECASE)
        found = audio_ext_re.findall(text)
        for u in found:
            items.append({'title': '', 'url': u})

    # If nothing found, include the raw response for debugging
    return render_template('app/html/redio.html', items=items, raw=raw)


# ===== NVIDIA NIM 代理 API =====
_NV_KEY = os.environ.get('NVIDIA_API_KEY', '')
_NV_URL = 'https://integrate.api.nvidia.com/v1/chat/completions'

def nvidia_chat_api():
    """NVIDIA NIM 聊天代理接口（SSE 流式转发）"""
    if request.method != 'POST':
        return _json_response({'error': '仅支持POST请求'}, 405)
    try:
        body = json.loads(request.get_data().decode('utf-8'))
    except Exception:
        return _json_response({'error': '请求体格式错误'}, 400)

    payload = {
        'model': body.get('model', 'nvidia/nemotron-3-ultra-550b-a55b'),
        'messages': body.get('messages', []),
        'temperature': body.get('temperature', 0.7),
        'top_p': 0.95,
        'max_tokens': min(body.get('max_tokens', 8192), 16384),
        'stream': True,
    }

    if not _NV_KEY:
        return _json_response({'error': '服务端未配置 NVIDIA API Key'}, 503)
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {_NV_KEY}'}
    try:
        resp = requests.post(_NV_URL, headers=headers, json=payload, timeout=(15, 120), stream=True)
        if resp.status_code >= 400:
            return _json_response({'error': f'API返回错误 {resp.status_code}', 'detail': resp.text[:1000]}, resp.status_code)

        def sse_gen():
            for raw in resp.iter_lines(decode_unicode=False):
                if raw is None:
                    continue
                line = raw.decode() if isinstance(raw, bytes) else raw
                yield f'{line}\n' if line else '\n'

        response = Response(stream_with_context(sse_gen()), content_type='text/event-stream', status=200)
        response.headers['Cache-Control'] = 'no-cache'
        response.headers['X-Accel-Buffering'] = 'no'
        return response
    except requests.exceptions.Timeout:
        return _json_response({'error': '请求超时'}, 504)
    except Exception as e:
        return _json_response({'error': str(e)}, 500)


# ===== 数据库管理功能 =====

@admin_required
def db_manage_page():
    """数据库管理页面（仅管理员可访问）"""
    username = session.get(SESSION_KEY, '')
    return render_template('pages/db_manage.html', username=username)


@admin_required
def db_tables_api():
    """获取所有数据表列表"""
    if request.method == 'OPTIONS':
        return _cors_preflight()
    try:
        with sql_db.DatabaseManager() as db:
            # 查询当前库所有用户表（MySQL 用 DATABASE()，不要用 PostgreSQL 的 'public'）
            rows = db._run(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name"
            )
            tables = [row[0] for row in rows] if rows else []
        return _json_response({'status': 'ok', 'tables': tables})
    except Exception as e:
        return _json_response({'status': 'error', 'message': str(e)})


@admin_required
def db_table_schema_api():
    """获取表结构（字段信息）"""
    if request.method == 'OPTIONS':
        return _cors_preflight()
    table_name = request.args.get('table', '')
    if not _safe_table(table_name):
        return _json_response({'status': 'error', 'message': '缺少表名或表名非法'})
    try:
        with sql_db.DatabaseManager() as db:
            # 查询表结构
            rows = db._run(
                "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_name = %s ORDER BY ordinal_position",
                (table_name,)
            )
            columns = []
            if rows:
                for row in rows:
                    columns.append({
                        'name': row[0],
                        'type': row[1],
                        'nullable': row[2],
                        'default': row[3]
                    })
        return _json_response({'status': 'ok', 'columns': columns})
    except Exception as e:
        return _json_response({'status': 'error', 'message': str(e)})


@admin_required
def db_query_api():
    """查询表数据（支持分页）"""
    if request.method == 'OPTIONS':
        return _cors_preflight()
    table_name = request.args.get('table', '')
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('pageSize', 20))
    if not _safe_table(table_name):
        return _json_response({'status': 'error', 'message': '缺少表名或表名非法'})
    try:
        with sql_db.DatabaseManager() as db:
            # 获取总记录数
            count_rows = db._run(f'SELECT COUNT(*) FROM "{table_name}"')
            total = count_rows[0][0] if count_rows else 0

            # 分页查询数据
            offset = (page - 1) * page_size
            rows = db._run(f'SELECT * FROM "{table_name}" LIMIT {page_size} OFFSET {offset}')

            # 获取列名
            col_rows = db._run(
                "SELECT column_name FROM information_schema.columns WHERE table_name = %s ORDER BY ordinal_position",
                (table_name,)
            )
            columns = [row[0] for row in col_rows] if col_rows else []

            # 转换为字典列表
            data = []
            if rows:
                for row in rows:
                    item = {}
                    for i, col in enumerate(columns):
                        value = row[i] if i < len(row) else None
                        # 处理特殊类型
                        if hasattr(value, 'isoformat'):
                            value = value.isoformat()
                        item[col] = value
                    data.append(item)

        return _json_response({
            'status': 'ok',
            'data': data,
            'total': total,
            'page': page,
            'pageSize': page_size,
            'columns': columns
        })
    except Exception as e:
        return _json_response({'status': 'error', 'message': str(e)})


@admin_required
def db_insert_api():
    """插入数据"""
    if request.method == 'OPTIONS':
        return _cors_preflight("POST, OPTIONS")
    if request.method != 'POST':
        return _json_response({'status': 'error', 'message': '请使用 POST 请求'})
    try:
        body = json.loads(request.get_data().decode('utf-8'))
        table_name = body.get('table', '')
        data = body.get('data', {})
    except Exception:
        return _json_response({'status': 'error', 'message': '请求数据格式错误'})
    if not _safe_table(table_name) or not data:
        return _json_response({'status': 'error', 'message': '缺少表名或数据'})
    try:
        with sql_db.DatabaseManager() as db:
            # 构建插入数据
            insert_data = {}
            for key, value in data.items():
                if key.lower() == 'id':
                    # ID 字段特殊处理
                    insert_data['id'] = {'values': str(value) if value else str(int(time.time() * 1000000))}
                else:
                    insert_data[key] = {'values': value}

            result = db.insert(table_name, insert_data)
            if result > 0:
                return _json_response({'status': 'ok', 'message': '插入成功'})
            else:
                return _json_response({'status': 'error', 'message': '插入失败'})
    except Exception as e:
        return _json_response({'status': 'error', 'message': str(e)})


@admin_required
def db_update_api():
    """更新数据"""
    if request.method == 'OPTIONS':
        return _cors_preflight("POST, OPTIONS")
    if request.method != 'POST':
        return _json_response({'status': 'error', 'message': '请使用 POST 请求'})
    try:
        body = json.loads(request.get_data().decode('utf-8'))
        table_name = body.get('table', '')
        row_id = body.get('id')
        data = body.get('data', {})
    except Exception:
        return _json_response({'status': 'error', 'message': '请求数据格式错误'})
    if not _safe_table(table_name) or not row_id or not data:
        return _json_response({'status': 'error', 'message': '缺少必要参数'})
    try:
        with sql_db.DatabaseManager() as db:
            result = db.update(table_name, data, '"id" = %s', (str(row_id),))
            if result > 0:
                return _json_response({'status': 'ok', 'message': '更新成功'})
            else:
                return _json_response({'status': 'error', 'message': '更新失败'})
    except Exception as e:
        error_msg = str(e)
        # 提供更友好的错误信息
        if 'unique constraint' in error_msg.lower() or 'duplicate key' in error_msg.lower():
            if 'username' in error_msg.lower():
                return _json_response({'status': 'error', 'message': '用户名已存在，请使用其他用户名'})
            else:
                return _json_response({'status': 'error', 'message': '违反唯一约束，该值已存在'})
        return _json_response({'status': 'error', 'message': error_msg})


@admin_required
def db_delete_api():
    """删除数据"""
    if request.method == 'OPTIONS':
        return _cors_preflight("POST, OPTIONS")
    if request.method != 'POST':
        return _json_response({'status': 'error', 'message': '请使用 POST 请求'})
    try:
        body = json.loads(request.get_data().decode('utf-8'))
        table_name = body.get('table', '')
        row_id = body.get('id')
    except Exception:
        return _json_response({'status': 'error', 'message': '请求数据格式错误'})
    if not _safe_table(table_name) or not row_id:
        return _json_response({'status': 'error', 'message': '缺少表名或ID'})
    try:
        with sql_db.DatabaseManager() as db:
            result = db.delete(table_name, '"id" = %s', (str(row_id),))
            if result > 0:
                return _json_response({'status': 'ok', 'message': '删除成功'})
            else:
                return _json_response({'status': 'error', 'message': '删除失败'})
    except Exception as e:
        return _json_response({'status': 'error', 'message': str(e)})


@admin_required
def db_sql_execute_api():
    """执行自定义 SQL 语句"""
    if request.method == 'OPTIONS':
        return _cors_preflight("POST, OPTIONS")
    if request.method != 'POST':
        return _json_response({'status': 'error', 'message': '请使用 POST 请求'})
    try:
        body = json.loads(request.get_data().decode('utf-8'))
        sql = body.get('sql', '').strip()
    except Exception:
        return _json_response({'status': 'error', 'message': '请求数据格式错误'})
    if not sql:
        return _json_response({'status': 'error', 'message': 'SQL 语句不能为空'})

    # 安全检查：禁止某些危险操作
    sql_upper = sql.upper()
    dangerous_keywords = [
        'DROP DATABASE', 'DROP SCHEMA', 'DROP TABLE', 'DROP VIEW',
        'DROP INDEX', 'DROP COLUMN', 'DROP USER', 'DROP ROLE',
        'TRUNCATE', 'RENAME TABLE', 'GRANT', 'REVOKE',
        'CREATE USER', 'ALTER USER',
    ]
    for keyword in dangerous_keywords:
        if keyword in sql_upper:
            return _json_response({'status': 'error', 'message': f'禁止执行包含 {keyword} 的操作'})

    try:
        with sql_db.DatabaseManager() as db:
            # 判断是查询还是修改操作
            is_query = sql_upper.startswith('SELECT') or sql_upper.startswith('SHOW') or sql_upper.startswith('DESCRIBE') or sql_upper.startswith('EXPLAIN')

            if is_query:
                # 查询操作
                rows = db._run(sql)
                if rows is None:
                    return _json_response({'status': 'error', 'message': '查询执行失败'})

                # 尝试获取列名（如果有结果）
                columns = []
                data = []
                if rows:
                    # 对于 SELECT 查询，尝试获取列信息
                    try:
                        # 简单处理：使用索引作为列名
                        if rows and len(rows) > 0:
                            columns = [f'column_{i}' for i in range(len(rows[0]))]
                            for row in rows:
                                item = {}
                                for i, value in enumerate(row):
                                    if hasattr(value, 'isoformat'):
                                        value = value.isoformat()
                                    item[columns[i]] = value
                                data.append(item)
                    except Exception:
                        # 如果转换失败，返回原始数据
                        data = [list(row) for row in rows]

                return _json_response({
                    'status': 'ok',
                    'message': f'查询成功，返回 {len(rows) if rows else 0} 条记录',
                    'data': data,
                    'columns': columns,
                    'rowCount': len(rows) if rows else 0
                })
            else:
                # 修改操作（INSERT, UPDATE, DELETE, CREATE, ALTER 等）
                result = db._run(sql)
                return _json_response({
                    'status': 'ok',
                    'message': 'SQL 执行成功',
                    'affected': result
                })
    except Exception as e:
        return _json_response({'status': 'error', 'message': f'SQL 执行错误: {str(e)}'})

# ===== 数据库管理功能结束 =====
