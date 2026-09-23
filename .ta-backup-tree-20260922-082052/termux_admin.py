# -*- coding: utf-8 -*-
"""
Termux 管理控制台（挂载在 /index）
==================================

在手机上以 Web 方式运维本机 Termux 环境，包含五个模块：

  概览  —— CPU / 内存 / 存储 / 电池 / 温度 / 网络 / 系统信息
  服务  —— runit(termux-services) 服务的启停、重启、自启开关、日志
  进程  —— 按 CPU/内存排序的进程列表，支持 kill
  文件  —— 浏览 / 上传 / 下载 / 在线编辑 / 新建 / 重命名 / 复制 / 打包 / 解压 / 改权限
  终端  —— 执行任意 shell 命令（带超时）

鉴权
----
令牌制，令牌来源优先级：
  1. 环境变量 ``TERMUX_ADMIN_TOKEN``
  2. ``$HOME/.termux_admin_token``（不存在时自动生成并落盘，权限 0600）
请求需带 ``X-Admin-Token`` 头、``?token=`` 查询参数，或 JSON 体中的 ``token`` 字段。
若浏览器已登录 mysite（Flask session 里有 auth_user），则自动放行，无需令牌。

安全边界
--------
所有文件操作被限制在「允许根目录」之下：``$HOME``、``$PREFIX``、``$TMPDIR``、
外部存储（``/storage/emulated/0``）。越界路径一律拒绝，避免误删 ``/`` 或 ``/system``。
"""

import os
import re
import io
import json
import time
import stat
import shutil
import secrets
import functools
import subprocess
import threading
import traceback

from flask import (
    request, session, jsonify, render_template, send_file, make_response,
)

# --------------------------------------------------------------------------
# 环境常量
# --------------------------------------------------------------------------

HOME = os.environ.get('HOME') or os.path.expanduser('~')
PREFIX = os.environ.get('PREFIX') or os.path.realpath(
    os.path.join(HOME, os.pardir, 'usr'))
SVDIR = os.environ.get('SVDIR') or os.path.join(PREFIX, 'var', 'service')
LOGDIR = os.environ.get('LOGDIR') or os.path.join(PREFIX, 'var', 'log')
TMPDIR = os.environ.get('TMPDIR') or os.path.join(PREFIX, 'tmp')

# 子进程用的 PATH：确保 Termux 命令与 Android 自带命令都能找到
_BASE_PATH = ':'.join([
    os.path.join(PREFIX, 'bin'),
    os.path.join(PREFIX, 'bin', 'applets'),
    '/system/bin',
    '/system/xbin',
])

MAX_OUTPUT = 200_000          # 单次命令输出截断长度（字符）
MAX_EDIT_BYTES = 2 * 1024 * 1024   # 在线编辑上限 2MB
MAX_UPLOAD_BYTES = 512 * 1024 * 1024  # 单次上传上限 512MB

# 页面构建标记。改前端后手动往上加一位即可：页面会把自身烘焙的版本号
# 与服务端 ``/index/health`` 返回的版本号比对，不一致就直接提示「你读到的是旧版」，
# 用来终结「改了到底有没有生效 / 浏览器是不是在读缓存」这类扯皮。
BUILD = '20260922.4'


# --------------------------------------------------------------------------
# 令牌
# --------------------------------------------------------------------------

_TOKEN_FILE = os.path.join(HOME, '.termux_admin_token')


def _load_token() -> str:
    tok = (os.environ.get('TERMUX_ADMIN_TOKEN') or '').strip()
    if tok:
        return tok
    try:
        with open(_TOKEN_FILE, 'r', encoding='utf-8') as f:
            tok = f.read().strip()
        if tok:
            return tok
    except OSError:
        pass
    tok = secrets.token_hex(8)
    try:
        fd = os.open(_TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(tok + '\n')
    except OSError:
        pass
    return tok


ADMIN_TOKEN = _load_token()


def _authed() -> bool:
    # 1) mysite 已登录用户直接放行
    try:
        from .views import check_auth            # 延迟导入，避免循环依赖
        if check_auth():
            return True
    except Exception:
        pass
    # 2) 管理令牌
    supplied = (request.headers.get('X-Admin-Token')
                or request.args.get('token')
                or '')
    if not supplied and request.method in ('POST', 'PUT', 'PATCH'):
        body = request.get_json(silent=True)
        if isinstance(body, dict):
            supplied = body.get('token') or ''
    return bool(supplied) and secrets.compare_digest(str(supplied), ADMIN_TOKEN)


def token_required(fn):
    """API 守卫：校验令牌 + 统一异常兜底，保证任何情况下都返回 JSON。"""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == 'OPTIONS':
            return _ok({'status': 'ok'}, 204)
        if not _authed():
            return jsonify({
                'status': 'error',
                'code': 'UNAUTHORIZED',
                'message': '未授权：请提供有效的管理令牌（?token=… 或 X-Admin-Token）',
            }), 401
        try:
            return fn(*args, **kwargs)
        except PathError as e:
            return jsonify({'status': 'error', 'code': 'BAD_PATH',
                            'message': str(e)}), 400
        except Exception as e:                    # noqa: BLE001 - 兜底
            traceback.print_exc()
            return jsonify({'status': 'error',
                            'message': '{}: {}'.format(type(e).__name__, e)}), 500
    return wrapper


def _ok(payload, status=200):
    if isinstance(payload, dict):
        payload.setdefault('status', 'ok')
    resp = make_response(jsonify(payload), status)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


# --------------------------------------------------------------------------
# 子进程执行
# --------------------------------------------------------------------------

def _run(cmd, timeout=15, cwd=None, shell=False, env_extra=None):
    """执行命令，返回 ``(rc, stdout, stderr)``。绝不抛异常。"""
    env = os.environ.copy()
    env['PATH'] = env.get('PATH') or _BASE_PATH
    if _BASE_PATH.split(':')[0] not in env['PATH'].split(':'):
        env['PATH'] = _BASE_PATH + ':' + env['PATH']
    env.setdefault('HOME', HOME)
    env.setdefault('PREFIX', PREFIX)
    env.setdefault('SVDIR', SVDIR)
    env.setdefault('LOGDIR', LOGDIR)
    env.setdefault('TMPDIR', TMPDIR)
    env['LANG'] = 'en_US.UTF-8'
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(
            cmd, shell=shell, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, timeout=timeout,
        )
        return (p.returncode,
                p.stdout.decode('utf-8', 'replace'),
                p.stderr.decode('utf-8', 'replace'))
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b'').decode('utf-8', 'replace') if isinstance(e.stdout, bytes) else (e.stdout or '')
        return 124, out, '命令超时（超过 {} 秒未结束）'.format(timeout)
    except FileNotFoundError as e:
        return 127, '', '命令不存在: {}'.format(e)
    except Exception as e:                        # noqa: BLE001
        return 1, '', '{}: {}'.format(type(e).__name__, e)


# --------------------------------------------------------------------------
# 路径安全
# --------------------------------------------------------------------------

class PathError(Exception):
    pass


def _allowed_roots():
    # 家目录的父级（/data/data/com.termux/files）也放行，否则「上级」按钮一按就越界；
    # 该目录下只有 home 与 usr，不构成风险。
    cands = [HOME, PREFIX, TMPDIR, os.path.join(HOME, os.pardir),
             '/storage/emulated/0', '/storage/emulated/999',
             os.path.join(HOME, 'storage')]
    roots = []
    for c in cands:
        try:
            rp = os.path.realpath(c)
        except OSError:
            continue
        if os.path.isdir(rp) and rp not in roots:
            roots.append(rp)
    return roots


def _safe(path, must_exist=False, must_be_dir=False):
    """把用户传来的路径规范化为绝对路径，并强制限制在允许根目录内。"""
    if not path:
        path = HOME
    path = os.path.expanduser(str(path))
    if not path.startswith('/'):
        path = os.path.join(HOME, path)
    rp = os.path.realpath(path)
    roots = _allowed_roots()
    if not any(rp == r or rp.startswith(r + os.sep) for r in roots):
        raise PathError('路径越界：{}（仅允许 {} 之下）'.format(
            rp, '、'.join(roots)))
    if must_exist and not os.path.exists(rp):
        raise PathError('路径不存在：{}'.format(rp))
    if must_be_dir and not os.path.isdir(rp):
        raise PathError('不是目录：{}'.format(rp))
    return rp


def _safe_name(name):
    """校验单个文件名/目录名。

    不接受任何路径分隔符与 ``..``：与其把 ``../escape`` 静默改名成 ``escape``
    （用户会得到一个自己没打算建的目录），不如直接报错讲清楚。
    """
    if name is None:
        raise PathError('缺少名称')
    name = str(name).strip()
    if name in ('', '.', '..'):
        raise PathError('非法名称：{!r}'.format(name))
    if '/' in name or '\\' in name:
        raise PathError('名称不能包含路径分隔符（/ 或 \\）：{!r}'.format(name))
    if '\x00' in name:
        raise PathError('非法名称（含空字节）')
    return name


def _human(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return '-'
    for unit in ('B', 'K', 'M', 'G', 'T'):
        if abs(n) < 1024:
            return '{:.1f}{}'.format(n, unit) if unit != 'B' else '{:.0f}B'.format(n)
        n /= 1024.0
    return '{:.1f}P'.format(n)


# --------------------------------------------------------------------------
# 页面与健康检查
# --------------------------------------------------------------------------

def index_page():
    """管理控制台首页。页面本身不校验令牌，由前端拿到令牌后调用 API。"""
    return render_template('pages/termux_admin.html',
                           token_file=_TOKEN_FILE, build=BUILD)


@token_required
def api_health():
    return _ok({'token_file': _TOKEN_FILE, 'home': HOME, 'prefix': PREFIX,
                'build': BUILD, 'time': time.strftime('%Y-%m-%d %H:%M:%S')})


# --------------------------------------------------------------------------
# 概览
# --------------------------------------------------------------------------

_TEMP_SKIP = ('pmih010x', 'bcl', 'ibat', 'ibat-lvl', 'vbat')


def _getprop(key):
    rc, out, _ = _run(['getprop', key], timeout=5)
    return out.strip() if rc == 0 else ''


def _uptime_load():
    rc, out, _ = _run(['uptime'], timeout=6)
    if rc != 0:
        return '', ''
    up = ''
    m = re.search(r'up\s+(.+?),\s+\d+\s+user', out)
    if not m:
        m = re.search(r'up\s+(.+?),\s+load average', out)
    if m:
        up = m.group(1).strip()
    load = ''
    m = re.search(r'load average[s]?:\s*(.+)', out)
    if m:
        load = m.group(1).strip()
    return up, load


# CPU 忙碌度：Android 下 /proc/stat 不可读，改用内核 cpufreq 计数器
# --------------------------------------------------------------------------
# 为什么不能用 top / /proc/stat（实测于 Android + Termux）：
#     $ cat /proc/stat      -> Permission denied
#     $ cat /proc/loadavg   -> Permission denied
#     $ cat /proc/uptime    -> Permission denied
# 于是 toybox ``top`` 拿不到任何数据，聚合行恒定输出
#     800%cpu  0%user  0%nice  0%sys  800%idle ...
# 任何基于 ``top`` 的「(total - idle) / total」都恒等于 **0**（这就是界面显示 0% 的原因）。
# 注意 ``uptime`` 能给出负载，是因为它走 sysinfo() 系统调用，不读 /proc/loadavg。
#
# 可用的替代数据源（不需要 root，覆盖全机所有进程）：
#     /sys/devices/system/cpu/cpufreq/policyN/stats/time_in_state
# 每行「频率 累计驻留时间」，单位 10ms，按频率升序排列。
# 试过但同样被拒的源：/proc/pressure/cpu(PSI)、/proc/schedstat、/dev/cpuctl/*/cpuacct.usage、
# /sys/fs/cgroup、dumpsys cpuinfo —— Android 对非 root 应用一律 403。
#
# 算法：间隔 _CPU_SAMPLE_SEC 采样两次求差，按频率加权得到「平均运行频率」，
# 再把它映射到该簇 [最低频, 最高频] 区间上：
#     avg_f  = Σ(freq × ΔT) / ΣΔT
#     active = (avg_f - f_min) / (f_max - f_min) × 100
# 即：全程停在最低频 = 0%，跑满最高频 = 100%。
#
# 为什么不直接用「最低频档 = 空闲」这个更简单的口径：
# 实测本机 governor(walt) 空闲时把核停在 **556800**（不是最低档 384000），
# 5 秒空转里 384000 档一个 tick 都没涨，于是 (1 - ΔT(min)/ΔT(total)) 恒等于 100%，
# 指标直接饱和失效。按频率区间归一化才有区分度。
#
# 关键坑：time_in_state 是 **per-policy（按簇）** 的。本机 8 核只有 2 个簇，
# 于是 cpu0..cpu5 数值完全一致、cpu6/cpu7 完全一致 —— 若逐核平均会把簇重复计数，
# 所以必须按 policy 目录取值，并用「增量指纹」去重后再平均。

_CPUFREQ_BASE = '/sys/devices/system/cpu/cpufreq'
_CPU_SAMPLE_SEC = 0.8        # 两次采样的间隔
_CPU_CACHE_SEC = 2.5         # 结果缓存，避免并发请求各自 sleep
_CPU_CACHE = {'t': 0.0, 'data': None}
_CPU_LOCK = threading.Lock()


def _read_time_in_state(path):
    """读 time_in_state，返回 {频率Hz: 累计驻留}；读不到返回 None。"""
    try:
        with open(path) as fh:
            raw = fh.read()
    except OSError:
        return None
    out = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                out[int(parts[0])] = int(parts[1])
            except ValueError:
                pass
    return out or None


def _read_int_file(path):
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _cpufreq_units():
    """列出 CPU 簇：[(名称, time_in_state 路径, cur_freq 路径, max_freq 路径)]。"""
    units = []
    try:
        names = sorted(
            (n for n in os.listdir(_CPUFREQ_BASE) if n.startswith('policy')),
            key=lambda s: int(s[6:]) if s[6:].isdigit() else 0)
    except OSError:
        names = []
    for name in names:
        d = os.path.join(_CPUFREQ_BASE, name)
        tis = os.path.join(d, 'stats', 'time_in_state')
        if os.path.exists(tis):
            units.append((name, tis, os.path.join(d, 'scaling_cur_freq'),
                          os.path.join(d, 'cpuinfo_max_freq')))
    if units:
        return units
    # 兜底：老内核没有 policyN 目录时逐核取，稍后靠增量指纹去重
    for i in range(os.cpu_count() or 1):
        d = os.path.join('/sys/devices/system/cpu', 'cpu%d' % i, 'cpufreq')
        tis = os.path.join(d, 'stats', 'time_in_state')
        if os.path.exists(tis):
            units.append(('cpu%d' % i, tis, os.path.join(d, 'scaling_cur_freq'),
                          os.path.join(d, 'cpuinfo_max_freq')))
    return units


def _proc_cpu_ticks():
    """所有可读进程 utime+stime 之和（jiffies，Android USER_HZ=100）。

    只作为 cpufreq 不可用时的兜底：Android 只允许看到自己 uid 的进程，
    且短命进程被回收后其 CPU 时间会从 /proc 消失（用脚本实测 5 次
    python 启动，差值仅 1 tick，几乎测不到），所以精度有限。
    """
    try:
        pids = os.listdir('/proc')
    except OSError:
        return None
    total = 0
    for pid in pids:
        if not pid.isdigit():
            continue
        try:
            with open('/proc/%s/stat' % pid, 'rb') as fh:
                data = fh.read()
        except OSError:
            continue
        cut = data.rfind(b')')          # comm 里可能有空格/括号，取最后一个 ')'
        if cut < 0:
            continue
        fields = data[cut + 2:].split()
        try:
            total += int(fields[11]) + int(fields[12])   # utime, stime
        except (IndexError, ValueError):
            continue
    return total


def _sample_cpu():
    cores = os.cpu_count() or 1
    info = {
        'cores': cores,
        'usage': None,       # 全机 CPU 活跃度（0=停在最低频，100=跑满最高频）
        'clusters': [],      # 每个簇的明细
        'freq': [],          # 每个簇平均运行频率（MHz）
        'load': '',          # 1/5/15 分钟负载（来自 uptime）
        'source': '',        # cpufreq | proc | ''
        'note': '',
    }
    _up, info['load'] = _uptime_load()

    units = _cpufreq_units()
    first = {}
    for name, tis, _c, _m in units:
        first[name] = _read_time_in_state(tis)

    if any(v for v in first.values()):
        time.sleep(_CPU_SAMPLE_SEC)
        seen = set()
        for name, _tis, cur_p, max_p in units:
            second = _read_time_in_state(_tis)
            a, b = first.get(name), second
            if not a or not b:
                continue
            keys = sorted(set(a) | set(b))
            if len(keys) < 2:
                continue
            delta = [max(0, b.get(k, 0) - a.get(k, 0)) for k in keys]
            total = sum(delta)
            if total <= 0:
                continue                       # 该簇已 offline，无增量
            sig = tuple(delta)
            if sig in seen:                    # 同一 policy 被重复列出
                continue
            seen.add(sig)
            f_min, f_max = keys[0], keys[-1]
            avg_f = sum(keys[i] * delta[i] for i in range(len(keys))) / float(total)
            cur = _read_int_file(cur_p)
            mx = _read_int_file(max_p)
            info['clusters'].append({
                'name': name,
                # 区间归一化活跃度：停在最低频=0，跑满最高频=100
                'active': round(
                    max(0.0, min(100.0, (avg_f - f_min) / float(f_max - f_min) * 100.0)), 1),
                # 参考值：非最低频档的时间占比（本机空闲时≈100%，参考意义有限）
                'busy': round((1.0 - delta[0] / float(total)) * 100.0, 1),
                'avg_mhz': round(avg_f / 1000.0),
                'cur_mhz': round(cur / 1000.0) if cur else None,
                'max_mhz': round(mx / 1000.0) if mx else round(f_max / 1000.0),
                'min_mhz': round(f_min / 1000.0),
                'top_mhz': round(f_max / 1000.0),
                'steps': len(keys),
            })
        if info['clusters']:
            info['usage'] = round(
                sum(c['active'] for c in info['clusters']) / len(info['clusters']), 1)
            info['freq'] = [c['avg_mhz'] for c in info['clusters']]
            info['source'] = 'cpufreq'

    if info['usage'] is None:                  # 兜底：进程 CPU 时间差
        t0 = _proc_cpu_ticks()
        time.sleep(_CPU_SAMPLE_SEC)
        t1 = _proc_cpu_ticks()
        if t0 is not None and t1 is not None and t1 >= t0:
            info['usage'] = round(
                (t1 - t0) / 100.0 / (_CPU_SAMPLE_SEC * cores) * 100.0, 1)
            info['source'] = 'proc'
            info['note'] = '兜底口径：仅统计 Termux 可见进程'

    if info['usage'] is None:
        info['note'] = '内核计数器不可读，无法测量 CPU'
    return info


def _cpu_info():
    """CPU 活跃度（带 2.5s 缓存，避免页面并发刷新各睡 0.8s）。"""
    with _CPU_LOCK:
        cached = _CPU_CACHE['data']
        if cached is not None and time.time() - _CPU_CACHE['t'] < _CPU_CACHE_SEC:
            return cached
        data = _sample_cpu()
        _CPU_CACHE['t'] = time.time()
        _CPU_CACHE['data'] = data
        return data


def _mem_info():
    """优先 ``free -m``；失败则退回解析 ``/proc/meminfo``。"""
    info = {}
    rc, out, _ = _run(['free', '-m'], timeout=8)
    if rc == 0:
        for line in out.splitlines():
            if line.lower().startswith('mem:'):
                parts = line.split()
                if len(parts) >= 3:
                    total, used, free = (float(parts[1]), float(parts[2]),
                                         float(parts[3]))
                    avail = float(parts[6]) if len(parts) >= 7 else free
                    info = {'total_mb': total, 'used_mb': used, 'free_mb': free,
                            'avail_mb': avail,
                            'used_pct': round(used / total * 100, 1) if total else None,
                            'source': 'free'}
            elif line.lower().startswith('swap:'):
                parts = line.split()
                if len(parts) >= 3:
                    info['swap_total_mb'] = float(parts[1])
                    info['swap_used_mb'] = float(parts[2])
    if not info:
        try:
            kv = {}
            with open('/proc/meminfo') as f:
                for line in f:
                    k, _, v = line.partition(':')
                    kv[k.strip()] = v.strip()
            total = float(kv.get('MemTotal', '0 kB').split()[0]) / 1024
            avail = float(kv.get('MemAvailable', '0 kB').split()[0]) / 1024
            free = float(kv.get('MemFree', '0 kB').split()[0]) / 1024
            info = {'total_mb': total, 'used_mb': total - avail, 'free_mb': free,
                    'avail_mb': avail,
                    'used_pct': round((total - avail) / total * 100, 1) if total else None,
                    'source': '/proc/meminfo'}
        except Exception:                          # noqa: BLE001
            pass
    return info


def _storage_info():
    rc, out, _ = _run(['df', '-kP'], timeout=10)
    if rc != 0:
        return []
    seen, rows = set(), []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        fs, total, used, avail, pct, mnt = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        try:
            total_i, used_i, avail_i = int(total), int(used), int(avail)
        except ValueError:
            continue
        key = (fs, mnt)
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            'fs': fs, 'mount': mnt,
            'total': total_i * 1024, 'used': used_i * 1024, 'avail': avail_i * 1024,
            'used_pct': float(pct.rstrip('%')) if pct.rstrip('%').replace('.', '').isdigit() else None,
            'total_h': _human(total_i * 1024), 'used_h': _human(used_i * 1024),
            'avail_h': _human(avail_i * 1024),
        })
    # 只保留关心的挂载点，避免刷屏
    want = ('/data', '/storage/emulated', '/storage/emulated/0', '/data/user/0',
            '/storage/emulated/999')
    picked = [r for r in rows if r['mount'].startswith(want)]
    if not picked:
        picked = rows[:4]
    # 同一 fs 去重（/data 与 /data/user/0 常是同一个块设备）
    uniq, seen_fs = [], set()
    for r in picked:
        if r['fs'] in seen_fs:
            continue
        seen_fs.add(r['fs'])
        uniq.append(r)
    return uniq


def _disk_usage(paths):
    """对指定目录做 ``du -sh``（较重，仅在 deep=1 时调用）。"""
    out = {}
    for p in paths:
        rc, o, _ = _run(['du', '-sh', p], timeout=45)
        if rc == 0 and o.strip():
            out[p] = o.split()[0]
    return out


def _battery_info():
    rc, out, _ = _run(['termux-battery-status'], timeout=10)
    if rc != 0 or not out.strip():
        return {'error': 'termux-battery-status 不可用（需安装 Termux:API 应用）'}
    try:
        return json.loads(out)
    except ValueError:
        return {'error': '返回内容无法解析', 'raw': out[:400]}


def _wifi_info():
    rc, out, _ = _run(['termux-wifi-connectioninfo'], timeout=10)
    if rc != 0 or not out.strip():
        return {'error': 'termux-wifi-connectioninfo 不可用'}
    try:
        return json.loads(out)
    except ValueError:
        return {'error': '返回内容无法解析', 'raw': out[:400]}


def _temperature_info():
    """扫描 /sys/class/thermal，聚合 CPU/GPU/SoC 类传感器。"""
    base = '/sys/class/thermal'
    zones, groups = [], {}
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return {'zones': [], 'groups': {}, 'max': None, 'avg': None}
    for n in names:
        d = os.path.join(base, n)
        if not n.startswith('thermal_zone') or not os.path.isdir(d):
            continue
        try:
            with open(os.path.join(d, 'type')) as f:
                ztype = f.read().strip()
            with open(os.path.join(d, 'temp')) as f:
                raw = int(f.read().strip())
        except (OSError, ValueError):
            continue
        if any(s in ztype.lower() for s in _TEMP_SKIP):
            continue
        celsius = raw / 1000.0 if abs(raw) > 1000 else float(raw)
        if celsius < -20 or celsius > 150:
            continue
        zones.append({'zone': n, 'type': ztype, 'celsius': round(celsius, 1)})
        if ztype.startswith('cpu-'):
            key = 'CPU'
        elif ztype.startswith('cpuss'):
            key = 'CPU集群'
        elif ztype.startswith('gpuss'):
            key = 'GPU'
        elif ztype.startswith('aoss'):
            key = 'SoC'
        elif ztype.startswith('ddr'):
            key = '内存'
        elif ztype.startswith('mdmss'):
            key = '基带'
        elif ztype.startswith('camera'):
            key = '摄像头'
        elif ztype.startswith('video'):
            key = '视频解码'
        else:
            key = '其他'
        g = groups.setdefault(key, {'max': None, 'count': 0, 'sum': 0.0})
        g['sum'] += celsius
        g['count'] += 1
        g['max'] = celsius if g['max'] is None else max(g['max'], celsius)
    for g in groups.values():
        g['avg'] = round(g['sum'] / g['count'], 1)
        g['max'] = round(g['max'], 1)
        g.pop('sum', None)
    temps = [z['celsius'] for z in zones]
    zones.sort(key=lambda z: -z['celsius'])
    return {
        'zones': zones[:24],
        'groups': groups,
        'max': round(max(temps), 1) if temps else None,
        'avg': round(sum(temps) / len(temps), 1) if temps else None,
        'sensor_count': len(zones),
    }


def _services_summary():
    svcs = _services()
    up = [s['name'] for s in svcs if s['state'] == 'up']
    down = [s['name'] for s in svcs if s['state'] != 'up']
    return {'total': len(svcs), 'up': len(up), 'down': len(down),
            'up_names': up, 'down_names': down}


def _python_info():
    rc, out, _ = _run(['python3', '-V'], timeout=8)
    ver = (out or '').strip()
    rc2, out2, _ = _run(['uname', '-r'], timeout=5)
    return {'python': ver, 'kernel': (out2 or '').strip()}


@token_required
def api_overview():
    deep = request.args.get('deep') in ('1', 'true', 'yes')
    up, load = _uptime_load()
    cpu = _cpu_info()
    data = {
        'system': {
            'model': _getprop('ro.product.model'),
            'brand': _getprop('ro.product.brand'),
            'device': _getprop('ro.product.device'),
            'android': _getprop('ro.build.version.release'),
            'sdk': _getprop('ro.build.version.sdk'),
            'abi': _getprop('ro.product.cpu.abi'),
            'hostname': (_run(['uname', '-n'], timeout=5)[1] or '').strip(),
            'kernel': (_run(['uname', '-r'], timeout=5)[1] or '').strip(),
            'uptime': up,
            'load': cpu.get('load') or load,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        },
        'termux': {
            'version': os.environ.get('TERMUX_VERSION', ''),
            'api_version': os.environ.get('TERMUX_API_VERSION', ''),
            'app_pid': os.environ.get('TERMUX_APP_PID', ''),
            'package': os.environ.get('TERMUX_APP_PACKAGE_MANAGER', ''),
            'home': HOME, 'prefix': PREFIX,
        },
        'cpu': cpu,
        'memory': _mem_info(),
        'storage': _storage_info(),
        'battery': _battery_info(),
        'wifi': _wifi_info(),
        'temperature': _temperature_info(),
        'services_summary': _services_summary(),
        'python': _python_info(),
    }
    if deep:
        data['disk_usage'] = _disk_usage([HOME, os.path.join(HOME, 'mysite'), PREFIX])
    return _ok(data)


# --------------------------------------------------------------------------
# 服务（runit / termux-services）
# --------------------------------------------------------------------------

_SVC_RE = re.compile(r'^[A-Za-z0-9._-]+$')


def _services():
    out = []
    try:
        names = sorted(os.listdir(SVDIR))
    except OSError:
        return out
    for n in names:
        d = os.path.join(SVDIR, n)
        if not os.path.isdir(d):
            continue
        rc, o, e = _run(['sv', 'status', n], timeout=8)
        text = (o + e).strip()
        first = text.splitlines()[0] if text else 'unknown'
        if first.startswith('run:'):
            state = 'up'
        elif first.startswith('down:'):
            state = 'down'
        elif first.startswith('fail:'):
            state = 'fail'
        else:
            state = 'unknown'
        pid = None
        age = None
        title = first
        if state == 'up':
            # up 时形如 "run: mysite: (pid 19806) 39s; run: log: (pid 6228) 1292s"
            # 第一个 pid 才是主服务；down 时只有 log 的 pid，不能当主进程报出去。
            m = re.search(r'\(pid\s+(\d+)\)\s+(\d+)s', first)
            if m:
                pid = int(m.group(1))
                age = int(m.group(2))
        else:
            m = re.search(r'^down:\s*([^:]+):\s*(\d+)s', first)
            if m:
                age = int(m.group(2))
            else:
                m = re.search(r'^fail:\s*([^:]+):\s*(\d+)s', first)
                if m:
                    age = int(m.group(2))
        out.append({
            'name': n,
            'state': state,
            'pid': pid,
            'age': age,
            'autostart': not os.path.exists(os.path.join(d, 'down')),
            'has_log': os.path.isdir(os.path.join(d, 'log')),
            'raw': title,
        })
    return out


@token_required
def api_services():
    return _ok({'services': _services(), 'svdir': SVDIR})


@token_required
def api_service_action():
    body = request.get_json(silent=True) or {}
    name = str(body.get('name') or '').strip()
    action = str(body.get('action') or '').strip().lower()
    if not _SVC_RE.match(name):
        return _ok({'status': 'error', 'message': '非法服务名'}, 400)
    if not os.path.isdir(os.path.join(SVDIR, name)):
        return _ok({'status': 'error', 'message': '服务不存在：' + name}, 404)
    steps = []
    if action in ('start', 'up', 'enable'):
        if action == 'enable':
            rc, o, e = _run(['sv-enable', name], timeout=15)
            steps.append({'cmd': 'sv-enable ' + name, 'rc': rc, 'out': (o + e).strip()})
        rc, o, e = _run(['sv', 'up', name], timeout=20)
        steps.append({'cmd': 'sv up ' + name, 'rc': rc, 'out': (o + e).strip()})
    elif action in ('stop', 'down'):
        rc, o, e = _run(['sv', 'down', name], timeout=25)
        steps.append({'cmd': 'sv down ' + name, 'rc': rc, 'out': (o + e).strip()})
    elif action == 'disable':
        rc, o, e = _run(['sv-disable', name], timeout=15)
        steps.append({'cmd': 'sv-disable ' + name, 'rc': rc, 'out': (o + e).strip()})
    elif action == 'restart':
        # 先 down 再 up：proot/慢启动环境下比 sv restart 更可靠
        rc, o, e = _run(['sv', '-w', '12', 'down', name], timeout=25)
        steps.append({'cmd': 'sv down ' + name, 'rc': rc, 'out': (o + e).strip()})
        time.sleep(0.6)
        rc, o, e = _run(['sv', 'up', name], timeout=20)
        steps.append({'cmd': 'sv up ' + name, 'rc': rc, 'out': (o + e).strip()})
    else:
        return _ok({'status': 'error',
                    'message': '不支持的动作：' + action}, 400)

    # 等待状态稳定（最多 12 秒）
    target = 'down' if action in ('stop', 'down') else 'up'
    deadline = time.time() + 12
    state = 'unknown'
    while time.time() < deadline:
        cur = [s for s in _services() if s['name'] == name]
        state = cur[0]['state'] if cur else 'missing'
        if state == target:
            break
        time.sleep(0.8)
    cur = [s for s in _services() if s['name'] == name]
    return _ok({'action': action, 'name': name, 'state': state,
                'service': cur[0] if cur else None, 'steps': steps})


@token_required
def api_service_log():
    name = str(request.args.get('name') or '').strip()
    lines = max(1, min(int(request.args.get('lines') or 150), 2000))
    if not _SVC_RE.match(name):
        return _ok({'status': 'error', 'message': '非法服务名'}, 400)
    cands = [
        os.path.join(LOGDIR, 'sv', name, 'current'),
        os.path.join(LOGDIR, name, 'current'),
        os.path.join(SVDIR, name, 'log', 'current'),
    ]
    path = next((c for c in cands if os.path.isfile(c)), None)
    if not path:
        return _ok({'name': name, 'path': None, 'lines': [],
                    'message': '未找到日志文件（该服务可能没有 svlogd 日志）'})
    rc, out, err = _run(['tail', '-n', str(lines), path], timeout=15)
    if rc != 0 and not out:
        return _ok({'status': 'error', 'message': err.strip() or '读取日志失败'}, 500)
    size = os.path.getsize(path) if os.path.exists(path) else 0
    return _ok({'name': name, 'path': path, 'size': size,
                'size_h': _human(size),
                'lines': out.splitlines()})


# --------------------------------------------------------------------------
# 进程
# --------------------------------------------------------------------------

_PS_FIELDS = ('pid', 'ppid', 'user', 'cpu', 'mem', 'rss', 'stat', 'etime', 'args')


def _processes(sort='cpu', limit=50, filt=None):
    key = '-%mem' if sort in ('mem', 'memory', '%mem') else '-%cpu'
    rc, out, err = _run(
        ['ps', '-eo', 'pid,ppid,user,%cpu,%mem,rss,stat,etime,args',
         '--sort=' + key], timeout=20)
    if rc != 0 and not out:
        return [], err.strip()
    rows = []
    for line in out.splitlines():
        s = line.strip()
        if not s or s.startswith('PID') or s.split()[0] == 'PID':
            continue
        parts = s.split(None, len(_PS_FIELDS) - 1)
        if len(parts) < len(_PS_FIELDS):
            continue
        d = dict(zip(_PS_FIELDS, parts))
        try:
            d['pid'] = int(d['pid'])
            d['ppid'] = int(d['ppid'])
        except ValueError:
            continue
        try:
            d['cpu'] = float(d['cpu'])
        except ValueError:
            d['cpu'] = 0.0
        try:
            d['mem'] = float(d['mem'])
        except ValueError:
            d['mem'] = 0.0
        try:
            d['rss'] = int(d['rss'])
        except ValueError:
            d['rss'] = 0
        d['rss_h'] = _human(d['rss'] * 1024)
        if filt and filt.lower() not in (d['args'] or '').lower():
            continue
        rows.append(d)
    return rows[:max(1, min(int(limit or 50), 500))], ''


@token_required
def api_processes():
    sort = request.args.get('sort') or 'cpu'
    limit = request.args.get('limit') or 50
    filt = request.args.get('q') or ''
    rows, err = _processes(sort, limit, filt)
    return _ok({'processes': rows, 'sort': sort, 'error': err or None,
                'self_pid': os.getpid()})


_SIGNALS = {'TERM': 15, 'KILL': 9, 'INT': 2, 'HUP': 1, 'USR1': 10, 'USR2': 12}


@token_required
def api_process_kill():
    body = request.get_json(silent=True) or {}
    try:
        pid = int(body.get('pid'))
    except (TypeError, ValueError):
        return _ok({'status': 'error', 'message': '缺少合法 pid'}, 400)
    sig = str(body.get('signal') or 'TERM').upper()
    if sig not in _SIGNALS:
        return _ok({'status': 'error', 'message': '不支持的信号：' + sig}, 400)
    if pid <= 1:
        return _ok({'status': 'error', 'message': '拒绝操作 pid<=1 的系统进程'}, 400)
    protected = set()
    p = os.getpid()
    for _ in range(6):                      # 自身及其父进程链受保护
        if p <= 1:
            break
        protected.add(p)
        rc, out, _ = _run(['ps', '-o', 'ppid=', '-p', str(p)], timeout=5)
        try:
            p = int(out.strip())
        except ValueError:
            break
    if pid in protected:
        return _ok({'status': 'error',
                    'message': '拒绝终止管理控制台自身或其父进程（pid {}）'.format(pid)}, 400)
    rc, out, err = _run(['kill', '-s', sig, str(pid)], timeout=10)
    deadline = time.time() + 5
    alive = True
    while time.time() < deadline:
        rc2, o2, _ = _run(['ps', '-o', 'pid=', '-p', str(pid)], timeout=5)
        alive = bool(o2.strip())
        if not alive:
            break
        time.sleep(0.4)
    return _ok({'pid': pid, 'signal': sig, 'rc': rc,
                'output': (out + err).strip(), 'alive': alive})


# --------------------------------------------------------------------------
# 文件管理器
# --------------------------------------------------------------------------

_TEXT_EXT = {
    '.txt', '.md', '.py', '.js', '.ts', '.json', '.html', '.htm', '.css', '.scss',
    '.sh', '.bash', '.zsh', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf',
    '.log', '.env', '.xml', '.csv', '.tsv', '.sql', '.java', '.c', '.h', '.cpp',
    '.go', '.rs', '.php', '.rb', '.lua', '.vue', '.svelte', '.jsx', '.tsx',
    '.gitignore', '.service', '.plist', '.gradle', '.properties', '.diff', '.patch',
}


def _entry(path, name):
    full = os.path.join(path, name)
    try:
        st = os.lstat(full)
    except OSError:
        return None
    is_link = stat.S_ISLNK(st.st_mode)
    is_dir = os.path.isdir(full)
    ext = os.path.splitext(name)[1].lower()
    return {
        'name': name,
        'path': full,
        'is_dir': is_dir,
        'is_link': is_link,
        'link_target': os.readlink(full) if is_link else None,
        'size': st.st_size,
        'size_h': _human(st.st_size),
        'mtime': int(st.st_mtime),
        'mtime_h': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime)),
        'mode': oct(st.st_mode & 0o7777)[2:],
        'editable': (not is_dir) and ext in _TEXT_EXT and st.st_size <= MAX_EDIT_BYTES,
        'ext': ext,
    }


@token_required
def api_fs_list():
    path = _safe(request.args.get('path') or HOME, must_exist=True, must_be_dir=True)
    show_hidden = request.args.get('hidden') in ('1', 'true', 'yes')
    try:
        names = os.listdir(path)
    except PermissionError as e:
        return _ok({'status': 'error', 'code': 'EACCES',
                    'message': '无权限读取目录：{}（Termux 受 Android 沙箱限制，'
                               '/system 等目录不可读）'.format(path)}, 403)
    except OSError as e:
        return _ok({'status': 'error', 'message': str(e)}, 400)

    if not show_hidden:
        names = [n for n in names if not n.startswith('.')]
    dirs, files = [], []
    for n in sorted(names):
        e = _entry(path, n)
        if not e:
            continue
        (dirs if e['is_dir'] else files).append(e)

    parent = os.path.dirname(path.rstrip('/')) or '/'
    try:
        parent_ok = bool(_safe(parent))
    except PathError:
        parent_ok = False

    st = os.statvfs(path)
    return _ok({
        'path': path,
        'parent': parent if parent_ok else None,
        'entries': dirs + files,
        'counts': {'dirs': len(dirs), 'files': len(files)},
        'free': st.f_bavail * st.f_frsize,
        'free_h': _human(st.f_bavail * st.f_frsize),
        'total': st.f_blocks * st.f_frsize,
        'total_h': _human(st.f_blocks * st.f_frsize),
        'roots': _allowed_roots(),
        'writable': os.access(path, os.W_OK),
    })


@token_required
def api_fs_read():
    path = _safe(request.args.get('path'), must_exist=True)
    if os.path.isdir(path):
        return _ok({'status': 'error', 'message': '目标是目录，无法在线编辑'}, 400)
    size = os.path.getsize(path)
    if size > MAX_EDIT_BYTES:
        return _ok({'status': 'error',
                    'message': '文件过大（{} > {}），请下载后编辑'.format(
                        _human(size), _human(MAX_EDIT_BYTES))}, 400)
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except PermissionError:
        return _ok({'status': 'error', 'message': '无权限读取该文件'}, 403)
    except OSError as e:
        return _ok({'status': 'error', 'message': str(e)}, 400)
    if b'\x00' in raw[:8192]:
        return _ok({'status': 'error', 'message': '二进制文件，不支持在线编辑'}, 400)
    text = raw.decode('utf-8', 'replace')
    return _ok({'path': path, 'size': size, 'size_h': _human(size),
                'content': text, 'binary': False,
                'mode': oct(os.stat(path).st_mode & 0o7777)[2:]})


@token_required
def api_fs_write():
    body = request.get_json(silent=True) or {}
    path = _safe(body.get('path'))
    content = body.get('content')
    if content is None:
        return _ok({'status': 'error', 'message': '缺少 content'}, 400)
    if isinstance(content, str):
        raw = content.encode('utf-8')
    else:
        return _ok({'status': 'error', 'message': 'content 必须是字符串'}, 400)
    if len(raw) > MAX_EDIT_BYTES:
        return _ok({'status': 'error', 'message': '内容过大'}, 400)
    if os.path.isdir(path):
        return _ok({'status': 'error', 'message': '目标是目录'}, 400)
    existed = os.path.exists(path)
    if existed:
        try:
            os.replace(path, path + '.ta-bak')
        except OSError:
            pass
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(raw)
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass
    except PermissionError:
        return _ok({'status': 'error', 'message': '无权限写入该路径'}, 403)
    except OSError as e:
        return _ok({'status': 'error', 'message': str(e)}, 400)
    return _ok({'path': path, 'bytes': len(raw), 'created': not existed,
                'backup': path + '.ta-bak' if existed else None})


@token_required
def api_fs_mkdir():
    body = request.get_json(silent=True) or {}
    base = _safe(body.get('path') or HOME, must_exist=True, must_be_dir=True)
    name = _safe_name(body.get('name'))
    target = os.path.join(base, name)
    if os.path.exists(target):
        return _ok({'status': 'error', 'message': '已存在：' + name}, 400)
    try:
        os.makedirs(target, mode=0o755)
    except OSError as e:
        return _ok({'status': 'error', 'message': str(e)}, 400)
    return _ok({'path': target, 'created': True})


@token_required
def api_fs_mkfile():
    body = request.get_json(silent=True) or {}
    base = _safe(body.get('path') or HOME, must_exist=True, must_be_dir=True)
    name = _safe_name(body.get('name'))
    target = os.path.join(base, name)
    if os.path.exists(target):
        return _ok({'status': 'error', 'message': '已存在：' + name}, 400)
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.close(fd)
    except OSError as e:
        return _ok({'status': 'error', 'message': str(e)}, 400)
    return _ok({'path': target, 'created': True})


@token_required
def api_fs_rename():
    body = request.get_json(silent=True) or {}
    src = _safe(body.get('path'), must_exist=True)
    new_name = _safe_name(body.get('name'))
    dst = os.path.join(os.path.dirname(src.rstrip('/')), new_name)
    _safe(dst)                                   # 目标也必须在允许范围内
    if os.path.exists(dst) and os.path.realpath(dst) != os.path.realpath(src):
        return _ok({'status': 'error', 'message': '目标已存在：' + new_name}, 400)
    try:
        os.rename(src, dst)
    except OSError as e:
        return _ok({'status': 'error', 'message': str(e)}, 400)
    return _ok({'from': src, 'to': dst})


@token_required
def api_fs_copy():
    body = request.get_json(silent=True) or {}
    src = _safe(body.get('src'), must_exist=True)
    dst_dir = _safe(body.get('dst') or os.path.dirname(src), must_exist=True,
                    must_be_dir=True)
    dst = os.path.join(dst_dir, os.path.basename(src.rstrip('/')))
    if os.path.exists(dst):
        stem, ext = os.path.splitext(dst)
        dst = '{}-copy{}{}'.format(stem, time.strftime('%H%M%S'), ext)
    try:
        if os.path.isdir(src):
            shutil.copytree(src, dst, symlinks=True)
        else:
            shutil.copy2(src, dst)
    except OSError as e:
        return _ok({'status': 'error', 'message': str(e)}, 400)
    return _ok({'from': src, 'to': dst})


@token_required
def api_fs_delete():
    body = request.get_json(silent=True) or {}
    paths = body.get('paths')
    if isinstance(paths, str):
        paths = [paths]
    if not isinstance(paths, list) or not paths:
        return _ok({'status': 'error', 'message': '缺少 paths'}, 400)
    results = []
    for p in paths[:200]:
        try:
            real = _safe(p, must_exist=True)
            if real in (HOME, PREFIX, TMPDIR) or real in _allowed_roots():
                raise PathError('拒绝删除受保护的根目录：' + real)
            if os.path.isdir(real) and not os.path.islink(real):
                shutil.rmtree(real)
            else:
                os.remove(real)
            results.append({'path': real, 'ok': True})
        except Exception as e:                   # noqa: BLE001
            results.append({'path': str(p), 'ok': False, 'error': str(e)})
    ok = sum(1 for r in results if r['ok'])
    return _ok({'results': results, 'ok_count': ok, 'fail_count': len(results) - ok})


@token_required
def api_fs_chmod():
    body = request.get_json(silent=True) or {}
    path = _safe(body.get('path'), must_exist=True)
    mode = str(body.get('mode') or '').strip()
    if not re.match(r'^[0-7]{3,4}$', mode):
        return _ok({'status': 'error', 'message': '权限需为 3-4 位八进制，如 755'}, 400)
    try:
        os.chmod(path, int(mode, 8))
    except OSError as e:
        return _ok({'status': 'error', 'message': str(e)}, 400)
    return _ok({'path': path, 'mode': mode})


@token_required
def api_fs_pack():
    body = request.get_json(silent=True) or {}
    src = _safe(body.get('path'), must_exist=True)
    base = os.path.basename(src.rstrip('/'))
    name = _safe_name(body.get('name') or (base + '.tar.gz'))
    if not name.endswith(('.tar.gz', '.tgz', '.tar')):
        name += '.tar.gz'
    parent = os.path.dirname(src.rstrip('/'))
    try:
        _safe(parent)
    except PathError:
        parent = HOME                        # 落点越界时改放到家目录
    out = os.path.join(parent, name)
    flag = '-cf' if name.endswith('.tar') else '-czf'
    rc, o, e = _run(['tar', flag, out, '-C', parent, base], timeout=300)
    if rc != 0:
        return _ok({'status': 'error', 'message': (e or o).strip() or '打包失败',
                    'rc': rc}, 500)
    return _ok({'archive': out, 'size': os.path.getsize(out),
                'size_h': _human(os.path.getsize(out))})


@token_required
def api_fs_unpack():
    body = request.get_json(silent=True) or {}
    src = _safe(body.get('path'), must_exist=True)
    if os.path.isdir(src):
        return _ok({'status': 'error', 'message': '选择的是目录，请选择压缩包'}, 400)
    lower = src.lower()
    dest = _safe(body.get('dest') or os.path.dirname(src))
    base = os.path.basename(src)
    if lower.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar')):
        flag = '-xf'
        target = os.path.join(dest, re.sub(r'\.(tar\.gz|tgz|tar\.bz2|tar\.xz|tar)$',
                                           '', base))
        os.makedirs(target, exist_ok=True)
        rc, o, e = _run(['tar', flag, src, '-C', target], timeout=300)
    elif lower.endswith('.zip'):
        target = os.path.join(dest, base[:-4])
        os.makedirs(target, exist_ok=True)
        rc, o, e = _run(['unzip', '-o', src, '-d', target], timeout=300)
    elif lower.endswith('.gz'):
        target = os.path.join(dest, base[:-3])
        rc, o, e = _run(['sh', '-c', 'gunzip -c "$1" > "$2"', '_', src, target],
                        timeout=300)
    else:
        return _ok({'status': 'error',
                    'message': '不支持该格式（支持 tar.gz / tgz / tar / zip / gz）'}, 400)
    if rc != 0:
        return _ok({'status': 'error', 'message': (e or o).strip() or '解压失败',
                    'rc': rc}, 500)
    return _ok({'dest': target, 'output': (o + e).strip()[-4000:]})


@token_required
def api_fs_upload():
    dest = _safe(request.form.get('path') or HOME, must_exist=True, must_be_dir=True)
    files = request.files.getlist('files') or request.files.getlist('file')
    if not files:
        return _ok({'status': 'error', 'message': '没有收到文件'}, 400)
    results = []
    for fs in files:
        raw_name = (fs.filename or '').strip().replace('\\', '/')
        name = raw_name.split('/')[-1]
        if not name or name in ('.', '..'):
            results.append({'name': raw_name, 'ok': False, 'error': '非法文件名'})
            continue
        target = os.path.join(dest, name)
        try:
            _safe(target)
            fs.save(target)
            try:
                os.chmod(target, 0o644)
            except OSError:
                pass
            size = os.path.getsize(target)
            results.append({'name': name, 'path': target, 'ok': True,
                            'size': size, 'size_h': _human(size)})
        except Exception as e:                   # noqa: BLE001
            results.append({'name': name, 'ok': False, 'error': str(e)})
    ok = sum(1 for r in results if r.get('ok'))
    return _ok({'results': results, 'ok_count': ok, 'fail_count': len(results) - ok})


@token_required
def api_fs_download():
    path = _safe(request.args.get('path'), must_exist=True)
    if os.path.isdir(path):
        base = os.path.basename(path.rstrip('/')) or 'root'
        tmp = os.path.join(TMPDIR, '.ta-dl-{}.tar.gz'.format(int(time.time() * 1000)))
        rc, o, e = _run(['tar', '-czf', tmp, '-C', os.path.dirname(path.rstrip('/')), base],
                        timeout=300)
        if rc != 0:
            return _ok({'status': 'error', 'message': (e or o).strip() or '打包失败'}, 500)
        resp = send_file(tmp, as_attachment=True, download_name=base + '.tar.gz',
                         mimetype='application/gzip')
        resp.call_on_close(lambda: os.path.exists(tmp) and os.remove(tmp))
        return resp
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path))


# --------------------------------------------------------------------------
# 终端
# --------------------------------------------------------------------------

PRESETS = [
    {'label': '服务状态', 'cmd': 'sv status $(ls $SVDIR)', 'group': '服务'},
    {'label': '重启 mysite', 'cmd': 'sv restart mysite', 'group': '服务'},
    {'label': '内存占用', 'cmd': 'free -m', 'group': '系统'},
    {'label': '磁盘占用', 'cmd': 'df -h', 'group': '系统'},
    {'label': '高占用进程', 'cmd': "ps -eo pid,%cpu,%mem,rss,args --sort=-%cpu | head -15",
     'group': '系统'},
    {'label': '系统负载', 'cmd': 'uptime', 'group': '系统'},
    {'label': '家目录大小', 'cmd': 'du -sh ~/* 2>/dev/null | sort -h | tail -15',
     'group': '磁盘'},
    {'label': '已装软件包数', 'cmd': 'dpkg -l | wc -l', 'group': '包管理'},
    {'label': '可升级包', 'cmd': 'apt list --upgradable 2>/dev/null | head -20',
     'group': '包管理'},
    {'label': '网络连接', 'cmd': 'netstat -tunp 2>/dev/null || ss -tunp 2>/dev/null',
     'group': '网络'},
    {'label': '监听端口', 'cmd': 'ss -tlnp 2>/dev/null | head -25', 'group': '网络'},
    {'label': '最新日志', 'cmd': 'tail -n 50 mysite/mysite.log', 'group': '日志'},
]


@token_required
def api_presets():
    groups, order = {}, []
    for p in PRESETS:
        if p['group'] not in groups:
            groups[p['group']] = []
            order.append(p['group'])
        groups[p['group']].append(p)
    return _ok({'groups': [{'name': g, 'items': groups[g]} for g in order],
                'cwd': HOME})


@token_required
def api_exec():
    body = request.get_json(silent=True) or {}
    cmd = str(body.get('cmd') or '').strip()
    if not cmd:
        return _ok({'status': 'error', 'message': '命令为空'}, 400)
    if len(cmd) > 20000:
        return _ok({'status': 'error', 'message': '命令过长'}, 400)
    try:
        cwd = _safe(body.get('cwd') or HOME)
    except PathError:
        cwd = HOME
    if not os.path.isdir(cwd):
        cwd = HOME
    try:
        timeout = int(body.get('timeout') or 30)
    except (TypeError, ValueError):
        timeout = 30
    timeout = max(1, min(timeout, 180))
    t0 = time.time()
    rc, out, err = _run(['bash', '-c', cmd], timeout=timeout, cwd=cwd)
    ms = int((time.time() - t0) * 1000)
    return _ok({
        'cmd': cmd, 'cwd': cwd, 'rc': rc, 'ms': ms,
        'stdout': out[-MAX_OUTPUT:],
        'stderr': err[-20000:],
        'truncated': len(out) > MAX_OUTPUT,
    })
