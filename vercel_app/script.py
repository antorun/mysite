import json, base64
import requests
from bs4 import BeautifulSoup
from flask import request, Response, make_response
from . import sql_db

_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
_BM_HEADERS = {'User-Agent': _UA, 'Accept': 'application/json',
               'Origin': 'https://www.battlemetrics.com', 'Referer': 'https://www.battlemetrics.com/'}


def _json(data, status=200):
    return make_response(json.dumps(data, ensure_ascii=False), status, {'Content-Type': 'application/json'})


def _fetch_bm(server_id):
    try:
        r = requests.get(f'https://api.battlemetrics.com/servers/{server_id}', headers=_BM_HEADERS, timeout=10)
        if r.status_code == 200:
            d = r.json().get('data', {})
            a = d.get('attributes', {})
            det = a.get('details') or {}
            return {'name': a.get('name'), 'ip': a.get('ip'), 'port': a.get('port'),
                    'players': a.get('players'), 'maxPlayers': a.get('maxPlayers'),
                    'time': det.get('time'), 'version': det.get('version'),
                    'rank': a.get('rank'), 'status': a.get('status')}
        return {}
    except requests.RequestException as e:
        return {'error': str(e)}


def _fetch_text(url, **kw):
    try:
        r = requests.get(url, headers={'User-Agent': _UA}, timeout=15, **kw)
        return r.text if r.status_code == 200 else ''
    except requests.RequestException:
        return ''


# ---- BattleMetrics ----
def scum9996():      return _json(_fetch_bm('32723251'))
def scumplayer():    return _json(_fetch_bm('20456017'))
def serverinfo():
    sid = request.args.get('id', '20456017')
    return _json(_fetch_bm(sid)) if sid.isdigit() else _json({'error': 'Invalid server id'})


# ---- 微博热搜 ----
def wbhotword():
    t = _fetch_text('https://m.weibo.cn/api/container/getIndex?containerid=106003type%3D25%26t%3D3%26disable_hot%3D1%26filter_type%3Drealtimehot')
    try:
        return _json(json.loads(t)['data']['cards'][0]['card_group'])
    except Exception:
        return _json([])


# ---- 免费节点 ----
def freeVmessList():
    t = _fetch_text('https://github.com/search?q=免费节点&type=repositories&s=updated&o=desc')
    try:
        soup = BeautifulSoup(t, 'html.parser')
        el = soup.find('script', type='application/json', attrs={'data-target': 'react-app.embeddedData'})
        return _json({'results': json.loads(el.string)['payload']['results']}) if el else _json({})
    except Exception:
        return _json({})


def _github_snippet(url):
    t = _fetch_text(url)
    try:
        soup = BeautifulSoup(t, 'html.parser')
        div = soup.find('div', class_='snippet-clipboard-content notranslate position-relative overflow-auto')
        return div.get('data-snippet-clipboard-copy-content', '') if div else ''
    except Exception:
        return ''


def leetomlee123():
    content = _github_snippet('https://github.com/leetomlee123/freenode')
    return Response(content, mimetype='text/plain')


def mksshare():
    url = _github_snippet('https://github.com/mksshare/mksshare.github.io')
    if url:
        t = _fetch_text(url)
        try:
            return Response(base64.b64decode(t).decode('utf-8'), mimetype='text/plain')
        except Exception:
            pass
    return Response('', mimetype='text/plain')


def xiaoji235():
    return Response(_fetch_text('https://raw.githubusercontent.com/xiaoji235/airport-free/refs/heads/main/v2ray.txt'), mimetype='text/plain')


def freeservers():
    return Response(_fetch_text('https://proxy.v2gh.com/https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub'), mimetype='text/plain')


# ---- 服务器管理 ----
def server_add():
    a1, a2, a3, a4 = request.args['loc'], request.args['name'], request.args['id'], request.args['offi']
    with sql_db.DatabaseManager() as db:
        if db.insert('server', {'a1': {'values': a1}, 'a2': {'values': a2}, 'a3': {'values': a3}, 'a4': {'values': a4}}):
            return _json({'loc': a1, 'name': a2, 'id': a3, 'offi': a4})
        return make_response('', 500)


def sensor_upload():
    try:
        data = json.loads(request.form['sensor_data'])
        with sql_db.DatabaseManager() as db:
            if db.insert('sensor_data', data):
                return _json({'status': 'success', 'data': data})
        return make_response('', 500)
    except Exception as e:
        print(f"sensor_upload error: {e}")
        return make_response('', 500)
