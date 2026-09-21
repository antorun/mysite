import os
from flask import Flask, render_template
from . import views, script

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
_add('glm-chat/', views.glm_chat)
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


@app.errorhandler(500)
def _server_error(e):
    return render_template('errors/500.html'), 500


@app.errorhandler(404)
def _page_not_found(e):
    return render_template('errors/404.html'), 404