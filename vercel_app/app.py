import os
from flask import Flask, render_template
from . import views, script, termux_admin

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'staticfiles'),
    static_url_path='/static',
)
# 生产环境请通过环境变量 SECRET_KEY 注入；此处为兜底默认值
app.secret_key = os.environ.get('SECRET_KEY', 'vercel-flask-migration-secret')

# 修改 HTML 模板即时生效，无需重启服务（开发/迭代期友好；生产环境如有性能顾虑可设为 False）
app.config['TEMPLATES_AUTO_RELOAD'] = True

# 允许带 / 不带末尾斜杠都能匹配（兼容原 Django 路由行为）
app.url_map.strict_slashes = False


@app.after_request
def _no_store_html(resp):
    """HTML 页面禁止缓存。

    这些页面是随时会迭代的内部工具，而 Flask 默认不给任何缓存指令，
    浏览器（尤其手机端的第三方浏览器 / 运营商代理）就会自作主张地留住旧副本，
    改版后打开仍是老界面，很难分辨是"没部署"还是"读了缓存"。
    """
    ctype = resp.headers.get('Content-Type', '')
    if ctype.startswith('text/html'):
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
    return resp


def _add(rule, func, endpoint=None, methods=None):
    if not rule.startswith('/'):
        rule = '/' + rule
    app.add_url_rule(
        rule,
        view_func=func,
        endpoint=endpoint or rule,
        methods=methods or ['GET', 'POST', 'OPTIONS'],
    )


# 首页 / 公开页
_add('/', views.home_page, 'home')
_add('home/', views.home_page, 'home')
_add('main/', views.main)
_add('dashboard-home/', views.dashboard_home)

# 登录
_add('login/', views.login_page, 'login')
_add('login-api', views.login_api)
_add('register-api', views.register_api)
_add('logout/', views.logout_view)
_add('change-password-api', views.change_password_api)

# 人员管理
_add('users-manage/', views.users_manage_page)
_add('users-list-api', views.users_list_api)
_add('users-add-api', views.users_add_api)
_add('users-edit-api', views.users_edit_api)
_add('users-delete-api', views.users_delete_api)

# 数据库管理
_add('db-manage/', views.db_manage_page)
_add('api/db/tables', views.db_tables_api)
_add('api/db/schema', views.db_table_schema_api)
_add('api/db/query', views.db_query_api)
_add('api/db/insert', views.db_insert_api)
_add('api/db/update', views.db_update_api)
_add('api/db/delete', views.db_delete_api)
_add('api/db/sql', views.db_sql_execute_api)

# 工具页面
_add('reward/', views.reward)
_add('player/', views.player)
_add('M3U8_player/', views.M3U8_player)
_add('controller/', views.controller)
_add('download/', views.download_page)
_add('user-agreement/', views.user_agreement)
_add('about/', views.about_page)
_add('setting/', views.crosshairsetting)
_add('setting/crosshair/', views.crosshair)
_add('device/', views.device)
_add('ai-chat/', views.ai_chat)
_add('nvidia-chat/', views.nvidia_chat)
_add('mimo-chat/', views.mimo_chat)
_add('radio/', views.radio)

# 服务器
_add('wang/', views.scum9996, 'wang')
_add('server_search', views.server_search, 'server_search')
_add('server_info/', views.server_info)
_add('servers/', views.servers, 'servers')
_add('map_info/', views.map_info)

# API
_add('ai-chat-api', views.ai_chat_api)
_add('nvidia-chat-api', views.nvidia_chat_api)
_add('mimo-chat-api', views.mimo_chat_api)
_add('v1/chat/completions', views.openai_chat_completions)
_add('nvidia-chat-sync-api', views.nvidia_chat_sync_api)
_add('subscribe/', views.subscribe)
_add('get_vmess/', script.leetomlee123, 'get_vmess')
_add('wbhotword/', script.wbhotword)
_add('freeVmessList/', script.freeVmessList)
_add('leetomlee123/', script.leetomlee123, 'leetomlee123')
_add('mksshare/', script.mksshare)
_add('xiaoji235/', script.xiaoji235)
_add('freeservers/', script.freeservers)
_add('scumplayer/', script.scumplayer)
_add('servernum/', script.serverinfo, 'servernum')
_add('9996num/', script.scum9996, '9996num')
_add('scum/serveradd/', script.server_add)
_add('sensor_upload', script.sensor_upload)
_add('reward_proxy/', views.reward_proxy)
_add('sw-proxy.js', views.sw_proxy_js)

# 验证文件
_add('fec01a7cfaea0fc836af1470864e1efe.txt', views.verfy, 'verfy')
_add('.well-known/pki-validation/8897263DE544448583DF473226CE4FCB.txt', views.verfy2, 'verfy2')


# ============ Termux 管理控制台（入口 /index） ============
# 页面本身不校验令牌；/index/api/* 全部需要令牌或已登录会话。
_add('index', termux_admin.index_page, 'termux_admin')
_add('index/health', termux_admin.api_health)
_add('index/api/overview', termux_admin.api_overview)
_add('index/api/processes', termux_admin.api_processes)
_add('index/api/process/kill', termux_admin.api_process_kill)
_add('index/api/services', termux_admin.api_services)
_add('index/api/services/action', termux_admin.api_service_action)
_add('index/api/services/log', termux_admin.api_service_log)
_add('index/api/fs/list', termux_admin.api_fs_list)
_add('index/api/fs/read', termux_admin.api_fs_read)
_add('index/api/fs/write', termux_admin.api_fs_write)
_add('index/api/fs/mkdir', termux_admin.api_fs_mkdir)
_add('index/api/fs/mkfile', termux_admin.api_fs_mkfile)
_add('index/api/fs/rename', termux_admin.api_fs_rename)
_add('index/api/fs/copy', termux_admin.api_fs_copy)
_add('index/api/fs/delete', termux_admin.api_fs_delete)
_add('index/api/fs/chmod', termux_admin.api_fs_chmod)
_add('index/api/fs/pack', termux_admin.api_fs_pack)
_add('index/api/fs/unpack', termux_admin.api_fs_unpack)
_add('index/api/fs/upload', termux_admin.api_fs_upload)
_add('index/api/fs/download', termux_admin.api_fs_download)
# 内联预览（图片 / 视频 / 音频 / PDF）。支持 Range，视频才能拖动进度条。
_add('index/api/fs/inline', termux_admin.api_fs_inline)
_add('index/api/exec', termux_admin.api_exec)
_add('index/api/presets', termux_admin.api_presets)

# 传感器（Termux:API）。采样会真唤醒硬件，所以后端对帧数 / 路数 / 总时长都上了护栏，
# 前端实时模式默认关闭、切页自动停，并提供 cleanup 释放传感器资源。
_add('index/api/sensors', termux_admin.api_sensors)
_add('index/api/sensors/read', termux_admin.api_sensors_read)
_add('index/api/sensors/env', termux_admin.api_sensors_env)
_add('index/api/sensors/preview', termux_admin.api_sensors_preview)
_add('index/api/sensors/cleanup', termux_admin.api_sensors_cleanup)


@app.errorhandler(500)
def _server_error(e):
    return render_template('errors/500.html'), 500


@app.errorhandler(404)
def _page_not_found(e):
    return render_template('errors/404.html'), 404