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
import math
import time
import stat
import shutil
import secrets
import shlex
import functools
import tempfile
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


def _term_user():
    """终端提示符里的用户名。Termux 下 ``$USER`` 就是 ``u0_a383`` 这种，
    某些环境它是空的，所以一路兜到 uid —— 只要别让提示符空着就行。"""
    for get in (lambda: os.environ.get('USER'),
                lambda: os.environ.get('LOGNAME'),
                lambda: 'u{}'.format(os.getuid())):
        try:
            v = get()
        except Exception:                          # noqa: BLE001
            v = None
        if v:
            return str(v)
    return 'termux'


def _term_host():
    try:
        return os.uname()[1] or 'localhost'
    except Exception:                              # noqa: BLE001
        return 'localhost'


TERM_USER = _term_user()
TERM_HOST = _term_host()

# 页面构建标记。改前端后手动往上加一位即可：页面会把自身烘焙的版本号
# 与服务端 ``/index/health`` 返回的版本号比对，不一致就直接提示「你读到的是旧版」，
# 用来终结「改了到底有没有生效 / 浏览器是不是在读缓存」这类扯皮。
BUILD = '20260923.4'


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


def _uptime_seconds():
    """秒级启动时长，供前端每秒自增显示「运行时长」。

    toybox ``uptime`` 只输出到**分钟**（"up 3 days, 4:05"），所以界面上的运行时长
    永远不动、不会 +1。``/proc/uptime`` 在 Android 下被拒（见下方注释），
    但 ``CLOCK_BOOTTIME`` 是普通应用就能读的系统调用，语义与 /proc/uptime 第一列一致
    （含休眠时间）。失败时返回 None，前端会退化成「只显示不跳动」。
    """
    try:
        return round(float(time.clock_gettime(time.CLOCK_BOOTTIME)), 1)
    except (AttributeError, OSError, ValueError):
        return None


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
            'uptime_s': _uptime_seconds(),
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

_IMAGE_EXT = {
    '.png', '.jpg', '.jpeg', '.jfif', '.gif', '.webp', '.bmp', '.ico',
    '.svg', '.avif', '.heic', '.heif',
}
_VIDEO_EXT = {
    '.mp4', '.m4v', '.webm', '.mkv', '.mov', '.avi', '.3gp', '.ogv',
    '.ts', '.m2ts', '.mts', '.flv', '.wmv', '.m3u8',
}
_AUDIO_EXT = {
    '.mp3', '.m4a', '.aac', '.wav', '.flac', '.ogg', '.oga', '.opus', '.amr', '.mid',
}
_ARCHIVE_EXT = {'.zip', '.gz', '.tgz', '.tar', '.7z', '.rar', '.xz', '.bz2', '.zst'}

# 允许**按真实 MIME 内联**返回的类型。
#
# 白名单之外一律不放行 —— 这不是洁癖，是防「同源存储型 XSS」：
# 这个控制台把管理令牌存在 localStorage 里，如果 .html/.svg/.js/.xml 被按
# text/html / image/svg+xml 原样内联回来，用户点一下「预览」就等于让文件里的脚本
# 在本站源上执行，令牌会被直接读走。所以：
#   * .html/.js/.xml 这类文本 → 降级成 text/plain（能看源码，但绝不当页面执行）
#   * 其余未知类型 → 干脆走附件下载
_INLINE_MIME = {
    # 图片
    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.jfif': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
    '.bmp': 'image/bmp', '.ico': 'image/x-icon', '.avif': 'image/avif',
    '.heic': 'image/heic', '.heif': 'image/heif', '.svg': 'image/svg+xml',
    # 视频（含手机常见的 mkv / 3gp / m2ts；能不能解码是浏览器的事，
    # 至少 Content-Type 要给对，否则 Chrome 连尝试都不尝试）
    '.mp4': 'video/mp4', '.m4v': 'video/mp4', '.webm': 'video/webm',
    '.mkv': 'video/x-matroska', '.mov': 'video/quicktime',
    '.avi': 'video/x-msvideo', '.3gp': 'video/3gpp', '.ogv': 'video/ogg',
    '.ts': 'video/mp2t', '.m2ts': 'video/mp2t', '.mts': 'video/mp2t',
    '.flv': 'video/x-flv', '.wmv': 'video/x-ms-wmv',
    '.m3u8': 'application/vnd.apple.mpegurl',
    # 音频
    '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.aac': 'audio/aac',
    '.wav': 'audio/wav', '.flac': 'audio/flac', '.ogg': 'audio/ogg',
    '.oga': 'audio/ogg', '.opus': 'audio/opus', '.amr': 'audio/amr',
    '.mid': 'audio/midi',
    # 文档
    '.pdf': 'application/pdf',
}


def _kind_of_file(ext):
    """把一个扩展名归成前端好用的「种类」，前端不用再各自维护一份扩展名表。"""
    if ext in _IMAGE_EXT:
        return 'image'
    if ext in _VIDEO_EXT:
        return 'video'
    if ext in _AUDIO_EXT:
        return 'audio'
    if ext == '.pdf':
        return 'pdf'
    if ext in _TEXT_EXT:
        return 'text'
    if ext in _ARCHIVE_EXT:
        return 'archive'
    return 'binary'


def _entry(path, name):
    full = os.path.join(path, name)
    try:
        st = os.lstat(full)
    except OSError:
        return None
    is_link = stat.S_ISLNK(st.st_mode)
    is_dir = os.path.isdir(full)
    ext = os.path.splitext(name)[1].lower()
    kind = 'dir' if is_dir else _kind_of_file(ext)
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
        'kind': kind,
        # 能在页内直接渲染的（图片/视频/音频/PDF）；text 走编辑器，不算 preview
        'preview': kind in ('image', 'video', 'audio', 'pdf'),
        # 能内联返回真实 MIME 的才给「新标签打开」，否则只会变成下载
        'inline_ok': (not is_dir) and ext in _INLINE_MIME,
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


@token_required
def api_fs_inline():
    """内联返回文件，供页面里直接预览（图片 / 视频 / 音频 / PDF）。

    与下载的区别：
      * ``Content-Disposition: inline`` —— 不让浏览器弹保存框；
      * ``conditional=True`` —— 打开 **Range 支持**，这是视频能拖动进度条、
        边下边播的前提。没有它，``<video>`` 只有在这一个文件完全下完之后才肯播，
        大文件基本等于不能用；
      * 按白名单给真实 MIME（Android 上的 ``mimetypes`` 对 mkv/m2ts/m4a 常常一问三不知，
        一旦 Content-Type 不对，Chrome 连解码都不试）。

    不在白名单里的类型**绝不按原 MIME 返回**（防同源存储型 XSS，见 ``_INLINE_MIME``
    上面的注释）；文本降级成 text/plain，其余直接转成附件下载。
    """
    path = _safe(request.args.get('path'), must_exist=True)
    if os.path.isdir(path):
        return _ok({'status': 'error',
                    'message': '目录无法内联预览，请用下载（会自动打包成 tar.gz）'}, 400)
    name = os.path.basename(path)
    ext = os.path.splitext(path)[1].lower()
    mime = _INLINE_MIME.get(ext)
    as_text = False

    if mime is None:
        if ext in _TEXT_EXT:
            # 能看源码，但绝不当页面执行。Content-Type 等响应生成后统一规范
            # （Werkzeug 在 send_file 里和 Response 构造时各补一次 charset，
            #  事先拼进去就会变成 "text/plain; charset=utf-8; charset=utf-8"）。
            mime, as_text = 'text/plain', True
        else:
            return send_file(path, as_attachment=True, download_name=name)

    try:
        resp = send_file(path, mimetype=mime, as_attachment=False,
                         download_name=name, conditional=True)
    except PermissionError:
        return _ok({'status': 'error', 'message': '无权限读取该文件'}, 403)
    except OSError as e:
        return _ok({'status': 'error', 'message': str(e)}, 400)

    if as_text:
        resp.headers['Content-Type'] = 'text/plain; charset=utf-8'

    # 媒体给一小段私有缓存：拖动进度条时同一段不该反复回传（no-store 会让每次 seek
    # 都重新取一遍）。私有 = 只许本机浏览器缓存，令牌在 URL 里，别让中间代理留下副本。
    resp.headers['Cache-Control'] = 'private, max-age=300'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Accept-Ranges'] = 'bytes'   # 视频拖动进度条靠它
    if mime == 'image/svg+xml':
        # SVG 用 <img> 嵌进来时脚本本来就不会跑，但用户可能「新标签打开」直接访问它。
        # 加个 sandbox 把它钉死：渲染照旧，脚本禁掉。
        resp.headers['Content-Security-Policy'] = \
            "sandbox; default-src 'none'; style-src 'unsafe-inline'"
    return resp


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
                'cwd': HOME, 'home': HOME,
                'user': TERM_USER, 'host': TERM_HOST})


# 会改变当前目录的 shell 内建。只有命中才做「把新 cwd 带回来」那点额外工作 ——
# 绝大多数命令（ls / ps / df）跟 cwd 无关，不必每次多写一个临时文件。
_CD_HINT = re.compile(r'(^|[;&|(\s])(cd|pushd|popd)(\s|$|[;&|)])')


def _exec_with_cwd(cmd, timeout, cwd):
    """跑 ``cmd``，并把执行后的工作目录尽量带回来。

    ``bash -c`` 每次都是新 shell，所以用户敲的 ``cd`` 天然活不过这一次调用 ——
    真终端里它能留住，是因为 shell 一直活着。这里在命令末尾追加「把 ``$PWD``
    写进临时文件」，跑完读回来即可。临时文件写 TMPDIR（设备的 Termux tmp），随用随删。

    几种刻意不做包装的情况：

    * 命令里没有 ``cd`` / ``pushd`` / ``popd`` —— 目录不可能变，省一次写文件；
    * 命令里有 ``<<``（heredoc）—— 追加内容会被吞进 heredoc 体里，宁可不跟踪；
    * 用户命令是 ``exit`` / ``exec`` —— 追加段不会执行，文件为空，于是保持原 cwd，
      这与真终端一致（``exit`` 本来就只是退出，没改目录）。
    """
    snap = None
    if _CD_HINT.search(cmd) and '<<' not in cmd:
        try:
            fd, snap = tempfile.mkstemp(prefix='.ta-cwd-', dir=TMPDIR)
            os.close(fd)
        except OSError:
            snap = None
    if not snap:
        rc, out, err = _run(['bash', '-c', cmd], timeout=timeout, cwd=cwd)
        return rc, out, err, cwd, None

    wrapped = (cmd + '\n__ta_rc=$?\nprintf %s "$PWD" > ' + shlex.quote(snap)
               + '\nexit $__ta_rc')
    rc, out, err = _run(['bash', '-c', wrapped], timeout=timeout, cwd=cwd)

    got, after, cwderr = '', cwd, None
    try:
        with open(snap, 'r', encoding='utf-8', errors='replace') as f:
            got = f.read().strip()
    except OSError:
        got = ''
    finally:
        try:
            os.unlink(snap)
        except OSError:
            pass
    if got and got != cwd:
        try:
            after = _safe(got, must_be_dir=True)
        except PathError as e:
            # 目录确实变了，但新目录在放行范围外（比如 cd /）。命令本身跑成功了，
            # 所以不改判成失败，只把「没跟过去」的原因讲清楚 —— 否则提示符不动，
            # 用户会以为是终端坏了。
            after, cwderr = cwd, str(e)
    return rc, out, err, after, cwderr


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
    rc, out, err, cwd_after, cwd_err = _exec_with_cwd(cmd, timeout, cwd)
    ms = int((time.time() - t0) * 1000)
    return _ok({
        'cmd': cmd, 'cwd': cwd, 'cwd_after': cwd_after, 'cwd_error': cwd_err,
        'rc': rc, 'ms': ms,
        'stdout': out[-MAX_OUTPUT:],
        'stderr': err[-20000:],
        'truncated': len(out) > MAX_OUTPUT,
    })


# --------------------------------------------------------------------------
# 传感器（Termux:API）
# --------------------------------------------------------------------------
#
# ``termux-sensor`` 的脾气 —— 全是实测踩出来的，别再踩第二遍：
#
#   * ``-l`` 回 ``{"sensors": [...]}``。名字是**厂商私有**的，
#     形如 ``bmi26x Accelerometer Non-wakeup`` / ``OPLUS Fusion Light Sensor Next Gen``，
#     而且同一个名字会重复出现（不同物理实例），必须按名字去重。
#   * 采样输出**不是**一个 JSON 文档，而是一帧接一帧的流式 JSON ——
#     一帧里只包含「这一帧有更新」的那几个传感器。所以不能 ``json.loads`` 整段，
#     只能用 ``raw_decode`` 逐帧抠；帧间缺键是正常现象，不是丢数据。
#   * 事件型传感器（``motion_detect`` / ``stationary_detect`` / ``free_fall`` …）
#     只在事件发生时上报。安静时读到空，不等于它坏了。
#   * 名字全无效时它往 stdout 吐一句 ``No valid sensors were registered!``
#     但**退出码仍是 0**，只能靠字符串判断。
#   * 通道数完全看厂商：光照类能给你 16 个通道，可语义不公开。
#     能确定的物理量（加速度/陀螺/磁力/姿态/距离/步数）就按物理量解释，
#     解释不了的一律老实用「通道 N」原名展示，不猜。
#   * 采样会真的唤醒传感器硬件，**有耗电与发热代价**。所以这一层硬性限流：
#     单次 ≤12 个传感器、帧数 ≤120、帧间隔 ≥50ms、单次总时长 ≤30s、
#     列表结果缓存 3 分钟，并单独提供 ``-c`` 释放接口，绝不让它常驻吃电。

_SENSOR_LIST = {'t': 0.0, 'data': None}
_SENSOR_LIST_TTL = 180          # 秒。传感器集合基本不变，没必要每次都问一次系统
_STEP_MARK = {'t': 0.0, 'value': None, 'name': None}

# 传感器 HAL 一次只肯服务一个监听者：两个请求撞在一起时，后到的那个会采到空。
# 而 Web 上「连点两下检测按钮」太常见了。所以所有 termux-sensor 调用都串行化，
# 且同一组参数在 1.5 秒内复用上次结果 —— 连点不会重复唤醒硬件。
_SENSOR_LOCK = threading.Lock()
_SENSOR_LAST = {}
_SENSOR_DEDUP_TTL = 1.5

MAX_SENSOR_PICK = 12            # 单次最多同时采样多少个
MAX_SENSOR_FRAMES = 120         # 单次最多采多少帧
MAX_SENSOR_SPAN_MS = 30000      # 单次采样总时长上限

# (正则, kind, 中文名, 单位, 分组)  —— 顺序敏感，先具体后宽泛
_SENSOR_RULES = (
    # ---- 运动类 ----
    (r'accelerometer-uncalibrated',
     'accel_raw', '加速度（未校准）', 'm/s²', 'motion'),
    (r'accelerometer', 'accel', '加速度', 'm/s²', 'motion'),
    (r'gyroscope-uncalibrated', 'gyro_raw', '陀螺仪（未校准）', 'rad/s', 'motion'),
    (r'gyroscope', 'gyro', '陀螺仪', 'rad/s', 'motion'),
    (r'magnetometer-uncalibrated', 'mag_raw', '磁力计（未校准）', 'µT', 'motion'),
    (r'magnetometer', 'mag', '磁力计', 'µT', 'motion'),
    (r'game rotation|geomag_rv', 'quat', '姿态旋转矢量（四元数）', '', 'motion'),
    (r'rotation vector', 'euler', '姿态旋转矢量（欧拉角）', '°', 'motion'),
    (r'gravity', 'gravity', '重力', 'm/s²', 'motion'),
    (r'linear_acceleration', 'linaccel', '线性加速度', 'm/s²', 'motion'),
    # ---- 环境类 ----
    (r'proximity|_prox|gesture prox', 'prox', '距离（接近）', '', 'env'),
    (r'light sensor|ambient light|^lux', 'light', '环境光', 'lx', 'env'),
    (r'cct', 'cct', '色温', 'lx', 'env'),
    (r'rgb', 'rgb', 'RGB 光', '', 'env'),
    (r'flicker', 'flicker', '闪烁检测', '', 'env'),
    (r'device_orient|rotation_detect|rotation detect', 'orient', '机身朝向', '', 'env'),
    # ---- 事件类 ----
    (r'step_detect', 'step_event', '步态事件', '', 'event'),
    (r'pedometer_minute', 'step_minute', '每分钟步数', '步', 'event'),
    (r'pedometer', 'step', '计步（累计）', '步', 'event'),
    (r'pick_up|pickup', 'pick_up', '拿起检测', '', 'event'),
    (r'stationary', 'stationary', '静止检测', '', 'event'),
    (r'motion_detect|motion_sense', 'motion_event', '运动检测', '', 'event'),
    (r'free_fall', 'free_fall', '自由落体', '', 'event'),
    (r'pocket', 'pocket', '口袋检测', '', 'event'),
    (r'lay_detect', 'lay', '平放检测', '', 'event'),
    (r'elevator', 'elevator', '电梯检测', '', 'event'),
    (r'flight', 'flight', '飞行场景', '', 'event'),
    (r'car_motion', 'car', '车载运动', '', 'event'),
    (r'sns_smd|significant', 'smd', '显著运动', '', 'event'),
    (r'activity_recognition', 'activity', '活动识别', '', 'event'),
    # ---- 系统内部 ----
    (r'sensor_logger|dynamic sensor manager', 'system', '系统内部传感器', '', 'system'),
)

_GROUP_LABEL = {'motion': '运动', 'env': '环境', 'event': '事件', 'system': '系统', 'other': '其他'}

# 体检/曲线里按这个顺序优先挑传感器
_KIND_ORDER = ('accel', 'gyro', 'gravity', 'mag', 'quat', 'euler',
               'light', 'prox', 'orient', 'step')

# 可以被当成「短名」解析的 token —— 比 _KIND_ORDER 宽：
# 未校准的三条（*_raw）、线性加速度、以及事件型细分，体检不主动采，
# 但用户/前端点名要的时候必须能解析到。
_SENSOR_ALIASES = frozenset(_KIND_ORDER) | frozenset((
    'accel_raw', 'gyro_raw', 'mag_raw', 'linaccel',
    'step_event', 'step_minute', 'pick_up', 'stationary', 'motion_event',
    'free_fall', 'pocket', 'lay', 'elevator', 'flight', 'car', 'smd', 'activity',
    'cct', 'rgb', 'flicker',
))

_COMPASS = ('北', '北偏东', '东北', '东偏北', '东', '东偏南', '东南', '南偏东',
            '南', '南偏西', '西南', '西偏南', '西', '西偏北', '西北', '北偏西')

_ORIENT_NAME = {0: '竖屏（正常）', 1: '横屏（左转）', 2: '竖屏（倒置）',
                3: '横屏（右转）'}

# 电池枚举翻成人话：原样的 PLUGGED_USB / NOT_CHARGING 又长又不好读
_BAT_PLUG = {'PLUGGED_AC': '交流充电器', 'PLUGGED_USB': 'USB', 'PLUGGED_WIRELESS': '无线充电',
             'PLUGGED_DOCK': '底座', 'UNPLUGGED': '未插电'}
_BAT_STATUS = {'CHARGING': '充电中', 'DISCHARGING': '放电中', 'NOT_CHARGING': '未充电',
               'FULL': '已充满', 'UNKNOWN': '未知'}


def _classify_sensor(name):
    """把厂商私有传感器名归类成 (kind, 中文名, 单位, 分组)。"""
    for rx, kind, label, unit, group in _SENSOR_RULES:
        if re.search(rx, name, re.I):
            return kind, label, unit, group
    return 'other', '未归类传感器', '', 'other'


def _kind_of(name):
    return _classify_sensor(name)[0]


def _parse_stream(text):
    """解析 termux-sensor 的流式 JSON（一帧一个对象，首尾相接）。"""
    dec = json.JSONDecoder()
    out, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i] in ' \t\r\n':
            i += 1
        if i >= n:
            break
        try:
            obj, j = dec.raw_decode(text, i)
        except ValueError:
            break
        if isinstance(obj, dict):
            out.append(obj)
        i = j
    return out


def _sensor_names(force=False):
    """列出可用传感器（去重保序，带缓存）。与采样共用一把锁，避免互相抢占。"""
    now = time.time()
    if (not force) and _SENSOR_LIST['data'] is not None \
            and now - _SENSOR_LIST['t'] < _SENSOR_LIST_TTL:
        return _SENSOR_LIST['data']
    with _SENSOR_LOCK:
        now = time.time()
        if (not force) and _SENSOR_LIST['data'] is not None \
                and now - _SENSOR_LIST['t'] < _SENSOR_LIST_TTL:
            return _SENSOR_LIST['data']
        rc, out, err = _run(['termux-sensor', '-l'], timeout=25)
        if rc != 0 or not out.strip():
            raise RuntimeError((err or out).strip()
                               or 'termux-sensor -l 无输出（需安装 Termux:API）')
        try:
            raw = json.loads(out)
        except ValueError:
            raise RuntimeError('无法解析 termux-sensor -l 输出')
        if isinstance(raw, dict):
            names = raw.get('sensors') or []
        elif isinstance(raw, list):
            names = raw
        else:
            names = []
        seen, uniq = set(), []
        for n in names:
            if isinstance(n, str) and n not in seen:
                seen.add(n)
                uniq.append(n)
        if not uniq:
            raise RuntimeError('系统未上报任何传感器')
        _SENSOR_LIST['data'] = uniq
        _SENSOR_LIST['t'] = now
        return uniq


def _first_of_kind(names, kind):
    for n in names:
        if _kind_of(n) == kind:
            return n
    return None


def _resolve_sensor(token, names):
    """把用户给的短名 / 物理量别名解析成真实传感器名。

    优先级：精确名 → 物理量别名（accel / gyro / light / step …）→ 包含匹配。
    别名必须排在包含匹配**之前**：否则 ``step`` 会被
    ``pedometer Oplus Step_detect Sensor`` 抢先命中 —— 那是个「步态事件」传感器，
    而用户要的显然是累计计步器 ``pedometer``，同理 ``light`` / ``prox`` 也会踩坑。
    """
    token = (token or '').strip()
    if not token:
        return None, '空名称'
    for n in names:
        if n == token:
            return n, None
    if token in _SENSOR_ALIASES:
        n = _first_of_kind(names, token)
        if n:
            return n, None
    hits = [n for n in names if token.lower() in n.lower()]
    if hits:
        return hits[0], None
    return None, '未找到传感器：{}'.format(token)


def _sensor_collect_raw(names, frames, delay):
    """真正去调 termux-sensor（不要在没加锁的情况下直接调它）。"""
    sel = ','.join(names)
    timeout = frames * delay / 1000.0 + 12
    rc, out, err = _run(
        ['termux-sensor', '-s', sel, '-n', str(frames), '-d', str(delay)],
        timeout=timeout)
    if 'No valid sensors were registered' in (out or ''):
        raise RuntimeError('这些传感器名无效：{}'.format(sel))
    if rc != 0 and not (out or '').strip():
        raise RuntimeError((err or '').strip() or 'termux-sensor 执行失败')
    series = {}
    for frame in _parse_stream(out or ''):
        for key, val in frame.items():
            vals = val.get('values') if isinstance(val, dict) else None
            if not isinstance(vals, list):
                continue
            try:
                row = [float(x) for x in vals]
            except (TypeError, ValueError):
                continue
            series.setdefault(key, []).append(row)
    for n in names:
        series.setdefault(n, [])
    return series


# 采样串行化 / 去抖 / 重试的锁与缓存见文件早先的 _SENSOR_LOCK 声明。
def _sensor_collect(names, frames, delay):
    """采样并拆成 {传感器名: [[每帧通道值], ...]}（带串行锁、去抖与重试）。"""
    key = (tuple(sorted(names)), frames, delay)
    hit = _SENSOR_LAST.get(key)
    if hit and time.time() - hit[0] < _SENSOR_DEDUP_TTL:
        return hit[1]

    with _SENSOR_LOCK:
        hit = _SENSOR_LAST.get(key)          # 等锁期间可能已经有人采过同一组
        if hit and time.time() - hit[0] < _SENSOR_DEDUP_TTL:
            return hit[1]
        series = _sensor_collect_raw(names, frames, delay)
        if not any(series.values()) and not all(
                _classify_sensor(n)[3] == 'event' for n in names):
            series = _sensor_collect_raw(names, frames, delay)
        _SENSOR_LAST[key] = (time.time(), series)
        if len(_SENSOR_LAST) > 12:           # 只留最近几组，别把内存当缓存用
            for k, _v in sorted(_SENSOR_LAST.items(), key=lambda kv: kv[1][0])[:4]:
                _SENSOR_LAST.pop(k, None)
    return series


# ---------------------------- 数值分析 ----------------------------

def _stat(vals):
    n = len(vals)
    if not n:
        return {'n': 0}
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n
    return {'n': n, 'mean': mean, 'std': var ** 0.5,
            'min': min(vals), 'max': max(vals), 'ptp': max(vals) - min(vals),
            'first': vals[0], 'last': vals[-1]}


def _norm(vec):
    return sum(v * v for v in vec) ** 0.5


def _rnd(x, n=3):
    try:
        return round(float(x), n)
    except (TypeError, ValueError):
        return x


def _compass(deg):
    return _COMPASS[int((deg % 360) / 22.5 + 0.5) % 16]


def _lux_level(v):
    if v is None:
        return '未知', 'info'
    if v < 2:
        return '全黑', 'warn'
    if v < 10:
        return '很暗（夜间或遮光）', 'info'
    if v < 50:
        return '昏暗', 'info'
    if v < 200:
        return '室内常规照明', 'ok'
    if v < 1000:
        return '明亮室内', 'ok'
    if v < 5000:
        return '阴天室外', 'info'
    return '强光（日照直射）', 'info'


def _tilt_from(vec):
    """由重力/加速度向量算前后倾角 pitch 与左右倾角 roll（度）。"""
    x, y, z = vec[0], vec[1], vec[2]
    pitch = math.degrees(math.atan2(-x, math.sqrt(y * y + z * z)))
    roll = math.degrees(math.atan2(y, z))
    return pitch, roll


def _posture_from(vec):
    """由重力方向判断机身姿态（人话版）。"""
    x, y, z = vec[0], vec[1], vec[2]
    ax, ay, az = abs(x), abs(y), abs(z)
    m = max(ax, ay, az)
    if m < 1e-6:
        return '姿态未知'
    if m == az:
        return '平放、屏幕朝上' if z > 0 else '平放、屏幕朝下'
    if m == ay:
        return '竖立（短边着地）' if y > 0 else '倒置（短边着地）'
    return '侧立（长边着地）'


def _motion_level(std_norm):
    """由合矢量波动判运动强度。"""
    if std_norm < 0.03:
        return '静止', 'ok'
    if std_norm < 0.35:
        return '轻微晃动（手持呼吸级）', 'info'
    if std_norm < 1.5:
        return '明显移动', 'info'
    return '剧烈晃动', 'warn'


def _quat_to_euler(q):
    """四元数 -> (方位角, 俯仰, 横滚) 度数。q 按 AOSP 的 (x,y,z,w) 排。

    方位角这里**取负**：实测这台机器上，同一时刻
    ``Rotation Vector``（3 通道欧拉）给 322.1°，而 ``sns_geomag_rv`` 四元数解出
    ``+38.2°`` —— 两者恰好关于 360 互补（322.1 + 38.2 ≈ 360.3），
    说明厂商这两族的 yaw 正方向相反。取负后两者对齐到 0.3° 以内，
    也才能和磁力计解出的方位角放在一起比较。
    """
    x, y, z, w = q[0], q[1], q[2], q[3]
    n = math.sqrt(x * x + y * y + z * z + w * w)
    if n < 1e-9:
        return None
    x, y, z, w = x / n, y / n, z / n, w / n
    yaw = math.degrees(math.atan2(2 * (w * z + x * y), 1 - 2 * (y * y + z * z)))
    pitch = math.degrees(math.asin(max(-1.0, min(1.0, 2 * (w * y - z * x)))))
    roll = math.degrees(math.atan2(2 * (w * x + y * z), 1 - 2 * (x * x + y * y)))
    return (-yaw) % 360, pitch, roll


def _metric(label, value, unit='', hint='', level='ok'):
    return {'label': label, 'value': value, 'unit': unit, 'hint': hint, 'level': level}


def _note(text, level='info'):
    return {'text': text, 'level': level}


def _empty_series(kind, name, label, unit, group):
    if group == 'event':
        why = ('事件型传感器只在事件触发时才上报（运动检测、自由落体、口袋检测、拿起检测'
               '这类），安静时读到空是正常行为，不代表它坏了。')
    elif group == 'system':
        why = '系统内部传感器不向第三方应用开放，拿不到数据属正常。'
    else:
        why = ('本周期内没有上报。可能是它只在特定条件下才工作（例如息屏 / AOD 状态），'
               '也可能已被系统挂起；过一会儿再采一次通常就有了。')
    return {
        'name': name, 'kind': kind, 'label': label, 'unit': unit, 'group': group,
        'channels': 0, 'samples': 0, 'series': [], 'latest': [], 'stats': [],
        'summary': {}, 'metrics': [], 'level': 'info', 'silent': True,
        'notes': [_note(why, 'info')],
    }


def _sensor_analyze(name, series, ctx=None):
    """把一条传感器的原始采样序列加工成「指标 + 结论」。"""
    ctx = ctx or {}
    kind, label, unit, group = _classify_sensor(name)
    frames = [f for f in series.get(name) or [] if f]
    if not frames:
        return _empty_series(kind, name, label, unit, group)

    nch = max(len(f) for f in frames)
    frames = [list(f) + [0.0] * (nch - len(f)) for f in frames]
    chans = [list(c) for c in zip(*frames)]
    st = [_stat(c) for c in chans]
    mean_vec = [s['mean'] for s in st]
    metrics, notes = [], []
    lvl = ['ok']
    summary = {}

    def add(txt, lv='info'):
        notes.append(_note(txt, lv))
        lvl[0] = _worse(lvl[0], lv)

    # ---------- 3 轴矢量类：加速度 / 重力 ----------
    if kind in ('accel', 'accel_raw', 'gravity') and nch >= 3:
        mags = [_norm(f[:3]) for f in frames]
        ms = _stat(mags)
        pitch, roll = _tilt_from(mean_vec)
        posture = _posture_from(mean_vec)
        motion, mlv = _motion_level(ms['std'])
        summary.update(gravity_vec=mean_vec[:3], accel_mean=ms['mean'],
                       accel_std=ms['std'], posture=posture, motion=motion,
                       motion_level=mlv, tilt_pitch=pitch, tilt_roll=roll)
        metrics += [
            _metric('合矢量', _rnd(ms['mean']), 'm/s²',
                    '重力加速度基准 9.807 m/s²', 'ok'),
            _metric('分量均值', '{} / {} / {}'.format(_rnd(mean_vec[0]), _rnd(mean_vec[1]),
                                                  _rnd(mean_vec[2])), 'm/s²',
                    'X / Y / Z', 'ok'),
            _metric('波动（标准差）', _rnd(ms['std']), 'm/s²', '越小越稳', mlv),
            _metric('峰峰值', _rnd(ms['ptp']), 'm/s²', '采样窗口内最大最小之差', 'ok'),
            _metric('前后倾角', _rnd(pitch, 1), '°', '负=向后仰', 'ok'),
            _metric('左右倾角', _rnd(roll, 1), '°', '正=向右倾', 'ok'),
        ]
        add('运动状态：{}（合矢量波动 {} m/s²）'.format(motion, _rnd(ms['std'])), mlv)
        add('机身姿态：{}（前后倾 {}°，左右倾 {}°）'.format(
            posture, _rnd(pitch, 1), _rnd(roll, 1)), 'ok')
        if kind in ('accel', 'accel_raw'):
            dev = ms['mean'] - 9.807
            if abs(dev) > 1.5:
                add('合矢量与重力加速度偏差 {:+.2f} m/s²，说明存在持续外力或正在加速。'
                    .format(dev), 'warn')
            else:
                add('合矢量接近 9.807 m/s²，可视为只受重力（无持续外力）。', 'ok')

    # ---------- 线性加速度：重力已被厂商扣掉，方向无意义 ----------
    elif kind == 'linaccel' and nch >= 3:
        mags = [_norm(f[:3]) for f in frames]
        ms = _stat(mags)
        motion, mlv = _motion_level(ms['std'])
        summary.update(linaccel_mean=ms['mean'], linaccel_std=ms['std'],
                       linaccel_motion=motion, linaccel_motion_level=mlv)
        metrics += [
            _metric('残余加速度', _rnd(ms['mean']), 'm/s²',
                    '重力已由厂商扣除，只剩余外力分量', 'ok'),
            _metric('分量均值', '{} / {} / {}'.format(_rnd(mean_vec[0]), _rnd(mean_vec[1]),
                                                  _rnd(mean_vec[2])), 'm/s²',
                    'X / Y / Z', 'ok'),
            _metric('波动（标准差）', _rnd(ms['std']), 'm/s²', '越小越稳', mlv),
        ]
        add('扣除重力后的残余加速度均值 {} m/s²。'.format(_rnd(ms['mean'])), mlv)
        if ms['mean'] < 0.3:
            add('残余加速度极小，设备处于静止或匀速状态。', 'ok')
        else:
            add('残余加速度 {:.3f} m/s² 非零，设备确实在动（走动、手持摆动或乘车颠簸）。'
                .format(ms['mean']), 'info')
        notes.append(_note('注意：这个传感器已经由厂商扣掉重力，方向分量不再指向地心，'
                           '因此不能用来推算机身倾角与姿态 —— 想知道姿态请看「重力」'
                           '或「加速度」那一条。', 'info'))

    # ---------- 陀螺仪 ----------
    elif kind in ('gyro', 'gyro_raw') and nch >= 3:
        ws = [_norm(f[:3]) for f in frames]
        wstat = _stat(ws)
        deg = math.degrees(wstat['mean'])
        summary.update(gyro_mag=wstat['mean'], gyro_deg=deg, gyro_static=wstat['mean'] < 0.05)
        metrics += [
            _metric('角速度', _rnd(deg, 2), '°/s',
                    '原始 {:.4f} rad/s'.format(wstat['mean']), 'ok'),
            _metric('峰值角速度', _rnd(math.degrees(wstat['max']), 2), '°/s',
                    '原始 {:.4f} rad/s'.format(wstat['max']), 'ok'),
            _metric('角速度波动', _rnd(math.degrees(wstat['std']), 2), '°/s',
                    '转动是否均匀', 'ok'),
        ]
        if wstat['mean'] < 0.05:
            add('角速度 ≈ 0：设备没有在转动（真静止）。', 'ok')
        elif wstat['mean'] < 0.5:
            add('有缓慢转动（{:.1f} °/s），像是手持微调或缓慢转向。'.format(deg), 'info')
        elif wstat['mean'] < 3.0:
            add('正在转动（{:.1f} °/s）。'.format(deg), 'info')
        else:
            add('快速旋转（{:.1f} °/s），注意峰值 {:.1f} °/s。'
                .format(deg, math.degrees(wstat['max'])), 'warn')

    # ---------- 磁力计 ----------
    elif kind in ('mag', 'mag_raw') and nch >= 3:
        mags = [_norm(f[:3]) for f in frames]
        ms = _stat(mags)
        summary.update(mag_field=ms['mean'], mag_std=ms['std'])
        metrics += [
            _metric('磁场强度', _rnd(ms['mean'], 2), 'µT',
                    '未校准' if kind == 'mag_raw' else '地表常值 25–65 µT', 'ok'),
            _metric('分量均值', '{} / {} / {}'.format(_rnd(mean_vec[0], 2),
                                                  _rnd(mean_vec[1], 2),
                                                  _rnd(mean_vec[2], 2)), 'µT',
                    'X / Y / Z', 'ok'),
            _metric('强度波动', _rnd(ms['std'], 2), 'µT', '稳定性', 'ok'),
        ]
        if kind == 'mag_raw':
            add('这是未校准磁力计：读数里带着固定的硬铁/软铁偏置，绝对值偏高（或偏低）'
                '都属正常，不适合直接和地表磁场对比。要判断磁场是否异常，请看校准过的'
                '那条磁力计。', 'info')
        elif ms['mean'] < 15:
            add('磁场强度只有 {:.1f} µT，偏弱，可能被金属外壳屏蔽或未校准。'
                .format(ms['mean']), 'warn')
        elif ms['mean'] > 80:
            add('磁场强度 {:.1f} µT 明显高于地表常值，附近可能有磁体、扬声器或大电流导线。'
                .format(ms['mean']), 'warn')
        else:
            add('磁场强度 {:.1f} µT，处于地表正常范围。'.format(ms['mean']), 'ok')
        # 方位角：用重力向量做倾斜补偿（Android getOrientation 的简化式）
        g = ctx.get('gravity') or ctx.get('accel') or ctx.get('accel_raw')
        if g and len(g) >= 3:
            mx, my, mz = mean_vec[:3]
            gx, gy, gz = g[0], g[1], g[2]
            hx = my * gz - mz * gy
            hy = mz * gx - mx * gz
            if abs(hx) > 1e-6 or abs(hy) > 1e-6:
                az = math.degrees(math.atan2(hy, hx)) % 360
                summary['mag_azimuth'] = az
                metrics.append(_metric('磁方位角', _rnd(az, 1), '°',
                                       '{}（已用重力向量做倾斜补偿）'.format(_compass(az)),
                                       'ok'))
                add('磁力计指向约 {:.1f}°（{}）。'.format(az, _compass(az)), 'ok')
            else:
                add('磁场向量与重力方向平行，无法解出方位角（磁力计可能被强磁干扰）。',
                    'warn')
        else:
            add('本次没有一起采到加速度/重力，方位角无法做倾斜补偿，故略去。', 'info')

    # ---------- 旋转矢量：3 通道当欧拉角、4/5 通道当四元数 ----------
    elif kind in ('quat', 'euler') and nch >= 3:
        ang = None
        if nch >= 4:
            q = mean_vec[:4]
            ang = _quat_to_euler(q)
            # 名字里有 geomag / magnet 的才融合了磁力计，方位角才是绝对的；
            # 「Game Rotation Vector」是纯陀螺积分，方位角只是相对值。
            abs_heading = bool(re.search(r'geomag|magnet', name, re.I))
            summary['heading_absolute'] = abs_heading
            metrics.append(_metric('四元数', '{} / {} / {} / {}'.format(
                _rnd(q[0], 4), _rnd(q[1], 4), _rnd(q[2], 4), _rnd(q[3], 4)),
                '', '(x, y, z, w)，已归一化解算', 'ok'))
            if nch >= 5:
                acc = mean_vec[4]
                hint = ('该通道为 -1，表示系统未提供航向精度估计'
                        if acc is not None and acc < 0 else '越小越准')
                metrics.append(_metric('航向精度', _rnd(acc, 2), '°', hint, 'ok'))
            add('该传感器输出四元数（{} 通道），已归一化后解算成姿态角。'.format(nch), 'info')
            if abs_heading:
                add('它融合了磁力计，所以方位角是绝对方位（0° 指向磁北），可以直接当'
                    '指南针读。', 'ok')
            else:
                add('它不含磁力计（纯陀螺仪积分），方位角只是相对值：以开机时指向为零点，'
                    '放着不动也会缓慢漂移，不能当指南针用。', 'info')
        else:
            cols = [list(c) for c in zip(*[f[:3] for f in frames])]
            ang = (_stat(cols[0])['mean'] % 360,
                   _stat(cols[1])['mean'], _stat(cols[2])['mean'])
            summary['heading_absolute'] = True
            add('该传感器输出 3 通道欧拉角（方位 / 俯仰 / 横滚），按度数直接解读。', 'info')
        if ang:
            az, pt, rl = ang
            summary.update(azimuth=az, pitch=pt, roll=rl)
            metrics += [
                _metric('方位角', _rnd(az, 1), '°', _compass(az), 'ok'),
                _metric('俯仰角', _rnd(pt, 1), '°', '正=抬头', 'ok'),
                _metric('横滚角', _rnd(rl, 1), '°', '正=向右滚', 'ok'),
            ]
            add('姿态角：方位 {}°（{}），俯仰 {}°，横滚 {}°。'
                .format(_rnd(az, 1), _compass(az), _rnd(pt, 1), _rnd(rl, 1)), 'ok')
            if nch == 3:
                d = abs(st[0]['last'] - st[0]['first'])
                d = min(d, 360 - d) if d is not None else 0
                if d > 2:
                    add('方位角在采样窗口内变化了 {:.1f}°，设备正在转向。'.format(d),
                        'info')
                else:
                    add('方位角基本不变（变化 {:.1f}°），朝向稳定。'.format(d), 'ok')

    # ---------- 距离（接近） ----------
    elif kind == 'prox' and nch >= 1:
        vals = chans[0]
        v = vals[-1]
        near = v <= 1
        summary.update(prox=v, prox_near=near)
        metrics += [
            _metric('原始读数', _rnd(v, 2), '', '多数机型 0=贴近，5=远离', 
                    'warn' if near else 'ok'),
            _metric('判定', '被遮挡 / 贴近' if near else '未被遮挡',
                    '', '阈值按 0/1 判定，机型间存在差异', 'warn' if near else 'ok'),
            _metric('采样窗口波动', _rnd(_stat(vals)['ptp'], 2), '', '是否来回触发', 'ok'),
        ]
        if near:
            add('距离传感器读数 {}：前方有物体贴近（贴脸、放口袋，或屏幕朝下压在桌上）。'
                .format(_rnd(v, 2)), 'warn')
            if _stat(vals)['ptp'] > 0:
                add('窗口内读数有跳变，说明遮挡是间断发生的。', 'info')
        else:
            add('距离传感器读数 {}：前方无遮挡。'.format(_rnd(v, 2)), 'ok')

    # ---------- 光照 / 色温 / RGB / 闪烁：通道语义不公开，老实展示 ----------
    elif kind in ('light', 'cct', 'rgb', 'flicker', 'other') and nch >= 1:
        ch0 = _stat(chans[0])
        v = ch0['mean']
        metrics.append(_metric('通道 0', _rnd(v, 2), unit or '',
                               '厂商未公开通道语义，按序号展示', 'ok'))
        for i in range(1, min(nch, 8)):
            metrics.append(_metric('通道 {}'.format(i), _rnd(st[i]['mean'], 2),
                                   unit or '', '均值', 'ok'))
        if nch > 8:
            metrics.append(_metric('其余通道', '{} 个'.format(nch - 8), '',
                                   '通道过多，已折叠', 'info'))
        metrics.append(_metric('通道 0 波动', _rnd(ch0['std'], 3), unit or '',
                               '越小越稳定', 'ok'))
        notes.append(_note('该传感器 {} 个通道，厂商未公开各通道含义，'
                           '因此只按「通道 N」给序号与数值，不做物理量解释。'
                           .format(nch), 'info'))
        if kind == 'light':
            desc, lv = _lux_level(v)
            summary.update(lux=v, lux_desc=desc, lux_level=lv)
            metrics.append(_metric('亮度推断', desc, '', '以通道 0 近似 lux', lv))
            if v >= 0:
                notes.append(_note('通道 0 均值 {:.1f}，按量级推断为{}。'
                                   .format(v, desc), lv))
            lvl[0] = _worse(lvl[0], lv)
        if ch0['n'] > 1 and v > 1e-6:
            rel = ch0['std'] / abs(v)
            if rel > 0.5:
                notes.append(_note('采样窗口内光照波动达均值的 {:.0f}%，'
                                   '说明光路被遮挡或在移动。'.format(rel * 100), 'info'))
            else:
                notes.append(_note('采样窗口内光照稳定（波动 {:.0f}%）。'
                                   .format(rel * 100), 'ok'))

    # ---------- 机身朝向 ----------
    elif kind == 'orient' and nch >= 1:
        v = chans[0][-1]
        iv = int(round(v))
        name_ = _ORIENT_NAME.get(iv)
        summary.update(orient=iv, orient_name=name_)
        metrics += [
            _metric('枚举值', iv, '', 'AOSP 定义 0–3', 'ok'),
            _metric('朝向', name_ or '厂商扩展枚举（超出 AOSP 0–3）', '',
                    '' if name_ else '数值对不上标准定义，不做猜测',
                    'ok' if name_ else 'info'),
        ]
        if name_:
            notes.append(_note('机身朝向为{}。'.format(name_), 'ok'))
        else:
            notes.append(_note('朝向枚举值 {} 落在 AOSP 定义（0–3）之外，'
                               '该厂商可能自行扩展，仅如实显示原始值。'.format(iv), 'info'))

    # ---------- 计步 ----------
    elif kind == 'step' and nch >= 1:
        v = chans[0][-1]
        summary['step'] = v
        metrics.append(_metric('累计步数', int(v) if abs(v) < 1e12 else _rnd(v), '步',
                               '开机以来累计', 'ok'))
        prev = _STEP_MARK['value'] if _STEP_MARK['name'] == name else None
        if prev is not None:
            delta = v - prev
            summary['step_delta'] = int(delta)
            if delta > 0:
                metrics.append(_metric('距上次增加', int(delta), '步',
                                       '上次取样 {} 秒前'.format(
                                           int(time.time() - _STEP_MARK['t'])), 'info'))
                notes.append(_note('比上次取样多了 {} 步 —— 期间设备确实被带着走了。'
                                   .format(int(delta)), 'info'))
            else:
                metrics.append(_metric('距上次增加', 0, '步', '无变化', 'ok'))
                notes.append(_note('与上次取样相比步数不变，期间未检测到走路。', 'ok'))
        else:
            notes.append(_note('首次读取这个计步器，先把基数 {} 步记下来；'
                               '下次再读就能算出期间走了多少步。'.format(int(v)), 'ok'))
        _STEP_MARK.update(t=time.time(), value=v, name=name)

    # ---------- 其它事件型 ----------
    elif group == 'event':
        non_zero = [f for f in frames if any(abs(x) > 1e-9 for x in f)]
        metrics += [
            _metric('采样帧数', len(frames), '帧', '', 'ok'),
            _metric('含事件帧', len(non_zero), '帧', '非零即触发', 'info'),
            _metric('最新值', ' / '.join(str(_rnd(x, 2)) for x in frames[-1][:6]), '',
                    '', 'ok'),
        ]
        if non_zero:
            notes.append(_note('采样窗口内捕获到 {} 帧事件。'.format(len(non_zero)),
                               'info'))
        else:
            notes.append(_note('采样窗口内没有事件上报。事件型传感器只在触发时才有值，'
                               '安静时不报是正常行为（如运动检测、自由落体、口袋检测）。',
                               'info'))

    # ---------- 兜底：只给通用统计 ----------
    else:
        metrics.append(_metric('通道数', nch, '', '', 'ok'))
        for i in range(min(nch, 6)):
            metrics.append(_metric('通道 {}'.format(i), _rnd(st[i]['mean'], 3),
                                   '', '均值', 'ok'))
        notes.append(_note('该传感器未纳入物理量解释表，仅提供原始通道统计。', 'info'))

    # ---------- 通用：首尾变化 ----------
    # 3 轴标准量上面已经给了更有意义的指标（倾角、方位角、角速度…），
    # 再补一句「通道 0 变化了多少」纯属噪声；只对多通道私有传感器输出。
    if nch > 3:
        for i in range(min(nch, 4)):
            c = chans[i]
            if len(c) >= 2:
                d = c[-1] - c[0]
                if abs(d) > 1e-9:
                    notes.append(_note('通道 {} 首尾变化 {:+g}。'.format(i, _rnd(d, 3)),
                                       'info'))

    return {
        'name': name, 'kind': kind, 'label': label, 'unit': unit, 'group': group,
        'channels': nch, 'samples': len(frames),
        'series': [[_rnd(x, 4) for x in c] for c in chans],
        'latest': [_rnd(x, 4) for x in frames[-1]],
        'stats': [{'mean': _rnd(s['mean'], 4), 'std': _rnd(s['std'], 4),
                   'min': _rnd(s['min'], 4), 'max': _rnd(s['max'], 4)}
                  for s in st],
        'summary': {k: (_rnd(v, 4) if isinstance(v, float) else v)
                    for k, v in summary.items()},
        'metrics': metrics, 'notes': notes,
        'level': lvl[0], 'silent': False,
    }


_LEVEL_RANK = {'ok': 0, 'info': 1, 'warn': 2, 'err': 3}


def _worse(a, b):
    return a if _LEVEL_RANK.get(a, 0) >= _LEVEL_RANK.get(b, 0) else b


def _build_ctx(series):
    """给磁力计准备重力向量（倾斜补偿要用）。"""
    ctx = {}
    for name, rows in (series or {}).items():
        k = _kind_of(name)
        if k in ('gravity', 'accel', 'accel_raw') and k not in ctx and rows:
            nch = max(len(r) for r in rows)
            if nch < 3:
                continue
            rows = [list(r) + [0.0] * (nch - len(r)) for r in rows]
            cols = list(zip(*rows))
            ctx[k] = [sum(c) / len(c) for c in cols[:3]]
    return ctx


# ---------------------------- 环境体检 ----------------------------

def _sensor_env_build(names, battery, series):
    """把采样结果 + 电池汇总成体检指标、一句话结论与告警清单。

    所有取值都从各传感器分析结果的 ``summary`` 里拿，不在这里重新解析原始通道 ——
    否则「合矢量怎么算」就会有两份实现，早晚对不上。
    """
    ctx = _build_ctx(series)
    an = {}
    all_analyses = []

    def score(a):
        """同 kind 撞车时谁上：有数据的优先，其次是方位角为绝对方量的。"""
        s = 0 if a.get('silent') else 10
        if (a.get('summary') or {}).get('heading_absolute'):
            s += 1
        return s

    for n in names:
        k = _kind_of(n)
        a = _sensor_analyze(n, series, ctx)
        all_analyses.append(a)
        # 同一个 kind 可能有多个物理实例（device_orient 与 oplus_rotation_detect、
        # Game Rotation Vector 与 sns_geomag_rv…），取分数高的那个进摘要表。
        prev = an.get(k)
        if prev is None or score(a) > score(prev):
            an[k] = a

    def summ(kind, key, default=None):
        a = an.get(kind) or {}
        return (a.get('summary') or {}).get(key, default)

    def pick(key, default=None):
        for k in ('gravity', 'accel', 'accel_raw', 'linaccel', 'quat', 'euler', 'mag',
                  'light', 'prox', 'orient', 'step', 'gyro', 'gyro_raw'):
            v = summ(k, key)
            if v is not None:
                return v
        return default

    findings, chips = [], []

    def find(lv, title, detail):
        findings.append({'level': lv, 'title': title, 'detail': detail})

    # ---- 姿态 / 运动 / 合矢量 ----
    posture = pick('posture')
    motion = pick('motion')
    accel_std = pick('accel_std')
    accel_mean = pick('accel_mean')
    if posture:
        chips.append(('姿态', posture, 'ok'))
    if motion:
        chips.append(('运动', motion, pick('motion_level') or 'info'))
    if accel_mean is not None:
        chips.append(('合矢量', '{} m/s²'.format(_rnd(accel_mean)), 'ok'))
        if abs(accel_mean - 9.807) > 1.5:
            find('warn', '合矢量偏离重力',
                 '合矢量 {:.2f} m/s² 与 9.807 m/s² 相差 {:+.2f}，说明存在持续外力或正在加速。'
                 .format(accel_mean, accel_mean - 9.807))
    if accel_std is not None and accel_std >= 1.5:
        find('warn', '设备正在剧烈晃动',
             '加速度合矢量波动 {:.2f} m/s²，远超静止水平（<0.03）。'.format(accel_std))

    # ---- 转动 ----
    gyro_mag = pick('gyro_mag')
    # 注意：gyro_mag 是 rad/s（保留 4 位），gyro_deg 是同一批数据换算出的 °/s。
    # 结论句必须复用 gyro_deg，否则「由 rad/s 反算度」会因舍入出现 0.43 / 0.42 这种
    # 同一张卡片里两个数的情况。
    gyro_deg = pick('gyro_deg')
    if gyro_mag is not None:
        chips.append(('角速度', '{:.2f} °/s'.format(gyro_deg or 0),
                      'ok' if gyro_mag < 0.05 else 'info'))

    # ---- 朝向（姿态矢量 vs 磁力计）----
    # 优先用「融合了磁力计、方位角是绝对量」的那一个（euler 或 geomag 四元数）；
    # 只有相对航向可用时也显示，但明确标注，免得被当成指南针。
    az_cands = []
    for k in ('euler', 'quat'):
        s = (an.get(k) or {}).get('summary') or {}
        if s.get('azimuth') is not None:
            az_cands.append((bool(s.get('heading_absolute')), s['azimuth']))
    azimuth, az_tag = None, ''
    if az_cands:
        abs_ones = [c for c in az_cands if c[0]]
        if abs_ones:
            azimuth = abs_ones[0][1]
        else:
            azimuth = az_cands[0][1]
            az_tag = '（相对航向）'
    mag_az = pick('mag_azimuth')
    if azimuth is not None:
        chips.append(('朝向', '{:.0f}° {}{}'.format(azimuth, _compass(azimuth), az_tag),
                      'ok'))
        if az_tag:
            find('info', '当前朝向只是相对值',
                 '这台机器上可用的姿态传感器不含磁力计，方位角以开机时指向为零点，'
                 '放着不动也会漂移，不能当指南针用。')
    if mag_az is not None:
        chips.append(('磁方位', '{:.0f}° {}'.format(mag_az, _compass(mag_az)), 'ok'))
    if azimuth is not None and mag_az is not None:
        d = abs((azimuth - mag_az + 180) % 360 - 180)
        if d > 45:
            find('info', '姿态朝向与磁力计差异较大',
                 '姿态矢量给出 {:.0f}°，磁力计给出 {:.0f}°，相差 {:.0f}°。磁力计在室内'
                 '（钢筋、扬声器、充电电流）偏几十度是常态；此处差异更大，'
                 '更像是有磁干扰或其中一路未校准，建议结合下面「磁场」一项一起看。'
                 .format(azimuth, mag_az, d))

    # ---- 磁场 ----
    mag_f = pick('mag_field')
    if mag_f is not None:
        chips.append(('磁场', '{:.1f} µT'.format(mag_f), 'ok'))
        if mag_f < 15 or mag_f > 80:
            find('warn', '磁场强度异常',
                 '磁场 {:.1f} µT 超出地表常值 25–65 µT，附近可能有磁体、扬声器或大电流'
                 '导线；此时指南针读数不可靠。'.format(mag_f))

    # ---- 光照 ----
    lux = pick('lux')
    if lux is not None:
        desc, lv = _lux_level(lux)
        chips.append(('环境光', '{:.0f} lx · {}'.format(lux, desc), lv))

    # ---- 遮挡 ----
    prox_v = pick('prox')
    prox_near = pick('prox_near')
    if prox_v is not None:
        chips.append(('距离', '{}（{}）'.format(_rnd(prox_v, 2),
                                            '遮挡' if prox_near else '无遮挡'),
                      'warn' if prox_near else 'ok'))
        if prox_near:
            find('info', '距离传感器被遮挡',
                 '读数 {}：前方有物体贴近 —— 贴脸通话、放口袋，或屏幕朝下压在桌面上。'
                 .format(_rnd(prox_v, 2)))

    # ---- 机身朝向 ----
    ov = pick('orient')
    if ov is not None:
        chips.append(('机身朝向', pick('orient_name') or '厂商扩展枚举 {}'.format(ov), 'ok'))

    # ---- 计步 ----
    step_v = pick('step')
    if step_v is not None:
        chips.append(('累计步数', '{} 步'.format(int(step_v)), 'ok'))
        delta = pick('step_delta')
        if delta:
            find('info', '期间有走动', '比上次取样多 {} 步。'.format(int(delta)))

    # ---- 电池 / 温度 ----
    bpct = btemp = bplug = bstat = None
    if battery and not battery.get('error'):
        bpct = battery.get('percentage', battery.get('level'))
        btemp = battery.get('temperature')
        bplug = battery.get('plugged')
        bstat = battery.get('status')
        chips.append(('电量', '{}%'.format(bpct if bpct is not None else '?'), 'ok'))
        if btemp is not None:
            lv = 'err' if btemp >= 45 else ('warn' if btemp >= 42 else 'ok')
            chips.append(('电池温度', '{} ℃'.format(btemp), lv))
        if bplug and bplug != 'UNPLUGGED':
            chips.append(('供电', '{}（{}）'.format(_BAT_PLUG.get(bplug, bplug),
                                                 _BAT_STATUS.get(bstat, bstat or '')), 'ok'))
        if btemp is not None and btemp >= 42:
            find('warn' if btemp < 45 else 'err', '电池温度偏高',
                 '电池 {} ℃（健康设备通常 ≤40 ℃）。若正在边充边用、长时间亮屏或跑重负载，'
                 '建议先停下来散热。'.format(btemp))
        if bplug and bplug != 'UNPLUGGED' and btemp is not None and btemp >= 40:
            find('info', '充电中温度升高',
                 '正在{}，充电本身就会发热；{} ℃ 尚在可观察区间，持续高于 42 ℃ 需留意。'
                 .format(_BAT_PLUG.get(bplug, bplug), btemp))
        cur = battery.get('current')
        if isinstance(cur, (int, float)) and abs(cur) > 0:
            chips.append(('电流', '{:.0f} mA'.format(abs(cur) / 1000.0),
                          'info' if abs(cur) > 1500 else 'ok'))
        if battery.get('health') and battery['health'] != 'GOOD':
            find('warn', '电池健康状态异常',
                 '系统上报 health={}，建议关注电池老化情况。'.format(battery['health']))
    else:
        find('info', '电量与温度不可读',
             (battery or {}).get('error') or 'termux-battery-status 无输出')

    # ---- 交叉推断 ----
    if lux is not None and prox_near and lux < 5:
        find('info', '疑似在口袋 / 包内或屏幕朝下',
             '环境光 {:.0f} lx（全黑量级）且距离传感器被遮挡，两个条件同时成立，'
             '基本可以判定设备处于密闭或贴面状态。'.format(lux))
    # 「静止」是一条正面结论，不该只在「平放」时才给 —— 竖立着静止也是静止。
    # 原来这里绑了 `'平放' in posture`：手机竖立且静止时一条结论都不输出，
    # 「逐项结论」整张卡片就成了空白（空态不解释自己，就会被当成功能坏了）。
    # 另外必须两路都真采到才算数，否则拿 None 当 0 会得出「静止」的假结论。
    if accel_std is not None and gyro_mag is not None \
            and accel_std < 0.05 and gyro_mag < 0.05:
        find('ok', '设备处于静止状态',
             '加速度波动 {:.3f} m/s²、角速度 {:.2f} °/s 都接近零，姿态{}。'
             .format(accel_std, gyro_deg or 0, posture or '未知'))

    # ---- 一句话结论 ----
    seg = []
    if posture:
        seg.append('设备{}'.format(posture))
    if motion:
        seg.append('当前{}'.format(motion))
    if lux is not None:
        seg.append('环境光约 {:.0f} lx（{}）'.format(lux, _lux_level(lux)[0]))
    if prox_v is not None:
        seg.append('距离传感器{}'.format('被遮挡' if prox_near else '无遮挡'))
    if azimuth is not None:
        seg.append('朝{}方向{}'.format(_compass(azimuth), '（相对值）' if az_tag else ''))
    if bpct is not None:
        tail = ''
        if bplug and bplug != 'UNPLUGGED':
            tail = '（{}'.format(_BAT_PLUG.get(bplug, bplug))
            tail += '，{} ℃）'.format(btemp) if btemp is not None else '）'
        seg.append('电量 {}%{}'.format(bpct, tail))
    verdict = ('；'.join(seg) + '。') if seg else '未采集到可用传感器数据，无法给出结论。'

    rank = {'err': 0, 'warn': 1, 'info': 2, 'ok': 3}
    findings.sort(key=lambda f: rank.get(f['level'], 9))

    return {
        'verdict': verdict,
        'chips': [{'label': a, 'value': b, 'level': c} for a, b, c in chips],
        'findings': findings,
        'analyses': all_analyses,
        'sampled': [a['name'] for a in all_analyses if not a.get('silent')],
        'silent': [a['name'] for a in all_analyses if a.get('silent')],
    }


@token_required
def api_sensors():
    """传感器清单（带分类与推荐组合），不触发采样。"""
    force = request.args.get('refresh') in ('1', 'true', 'yes')
    try:
        names = _sensor_names(force)
    except Exception as e:                        # noqa: BLE001
        return _ok({'status': 'error', 'code': 'SENSOR_UNAVAILABLE',
                    'message': str(e), 'sensors': [], 'groups': []})
    items = []
    for n in names:
        kind, label, unit, group = _classify_sensor(n)
        items.append({'name': n, 'kind': kind, 'label': label,
                      'unit': unit, 'group': group,
                      'group_label': _GROUP_LABEL.get(group, group),
                      'event': group == 'event'})
    groups, order = {}, []
    for it in items:
        g = it['group']
        if g not in groups:
            groups[g] = []
            order.append(g)
        groups[g].append(it)
    picks = []
    for kind in _KIND_ORDER:
        nm = _first_of_kind(names, kind)
        if nm:
            k, label, unit, group = _classify_sensor(nm)
            picks.append({'kind': kind, 'name': nm, 'label': label, 'unit': unit})
    return _ok({
        'sensors': items, 'total': len(items),
        'groups': [{'key': g, 'label': _GROUP_LABEL.get(g, g),
                    'count': len(groups[g])} for g in order],
        'picks': picks,
        'cached': not force and _SENSOR_LIST['data'] is not None,
        'limits': {'max_pick': MAX_SENSOR_PICK, 'max_frames': MAX_SENSOR_FRAMES,
                   'max_span_ms': MAX_SENSOR_SPAN_MS},
    })


def _sensor_read_params():
    """解析并夹紧采样参数（这里的上下限就是发热/耗电的护栏）。"""
    raw = (request.args.get('s') or '').strip()
    if not raw:
        return None, None, None, '缺少 s 参数（传感器名，多个用 | 分隔，支持短名）'
    try:
        frames = int(request.args.get('n') or 20)
    except (TypeError, ValueError):
        frames = 20
    try:
        delay = int(request.args.get('d') or 120)
    except (TypeError, ValueError):
        delay = 120
    frames = max(1, min(frames, MAX_SENSOR_FRAMES))
    delay = max(50, min(delay, 2000))
    if frames * delay > MAX_SENSOR_SPAN_MS:
        delay = max(50, MAX_SENSOR_SPAN_MS // frames)
    return raw, frames, delay, None


def _sensor_pick_list(raw):
    names_all = _sensor_names()
    want, missing = [], []
    for tok in re.split(r'[|,]', raw):
        tok = tok.strip()
        if not tok:
            continue
        nm, err = _resolve_sensor(tok, names_all)
        if nm is None:
            missing.append(tok)
        elif nm not in want:
            want.append(nm)
    return names_all, want[:MAX_SENSOR_PICK], missing


@token_required
def api_sensors_read():
    raw, frames, delay, err = _sensor_read_params()
    if err:
        return _ok({'status': 'error', 'message': err}, 400)
    names_all, want, missing = _sensor_pick_list(raw)
    if not want:
        return _ok({'status': 'error',
                    'message': '没有可用的传感器：{}'.format('、'.join(missing) or raw)},
                   400)
    t0 = time.time()
    try:
        series = _sensor_collect(want, frames, delay)
    except Exception as e:                        # noqa: BLE001
        return _ok({'status': 'error', 'message': str(e)}, 500)
    ms = int((time.time() - t0) * 1000)
    ctx = _build_ctx(series)
    analyses = [_sensor_analyze(n, series, ctx) for n in want]

    if request.args.get('fmt') == 'csv':
        import csv
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(['sensor', 'kind', 'channel', 'frame', 'value'])
        for a in analyses:
            for ci, col in enumerate(a['series']):
                for fi, v in enumerate(col):
                    w.writerow([a['name'], a['kind'], ci, fi, v])
        resp = make_response('\ufeff' + buf.getvalue())
        resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
        resp.headers['Content-Disposition'] = (
            'attachment; filename="sensors-{}.csv"'.format(time.strftime('%Y%m%d-%H%M%S')))
        resp.headers['Cache-Control'] = 'no-store'
        return resp

    return _ok({
        'requested': raw, 'selected': want, 'missing': missing,
        'frames': frames, 'delay_ms': delay, 'elapsed_ms': ms,
        'analyses': analyses,
        'latest': {a['name']: a['latest'] for a in analyses},
    })


@token_required
def api_sensors_env():
    """环境体检：一次采样 + 电池，汇总成结论与告警。"""
    try:
        names_all = _sensor_names()
    except Exception as e:                        # noqa: BLE001
        return _ok({'status': 'error', 'code': 'SENSOR_UNAVAILABLE',
                    'message': str(e)})
    picked, seen = [], set()
    for kind in _KIND_ORDER:
        nm = _first_of_kind(names_all, kind)
        if nm and nm not in seen:
            seen.add(nm)
            picked.append(nm)
    picked = picked[:MAX_SENSOR_PICK]
    frames, delay = 4, 200
    t0 = time.time()
    series, err = {}, None
    if picked:
        try:
            series = _sensor_collect(picked, frames, delay)
        except Exception as e:                    # noqa: BLE001
            err = str(e)
    ms = int((time.time() - t0) * 1000)
    battery = _battery_info()
    temp = _temperature_info()
    env = _sensor_env_build(picked, battery, series)
    env.update({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'elapsed_ms': ms, 'frames': frames, 'delay_ms': delay,
        'battery': battery,
        'soc': {'max': temp.get('max'), 'groups': temp.get('groups') or {}},
        'error': err,
    })
    return _ok(env)


@token_required
def api_sensors_cleanup():
    """释放传感器资源（``termux-sensor -c``）。实时监视结束后调用，避免常驻耗电。"""
    rc, out, err = _run(['termux-sensor', '-c'], timeout=15)
    return _ok({'rc': rc, 'stdout': out.strip()[:400], 'stderr': err.strip()[:400]})


@token_required
def api_sensors_preview():
    """一次性快速采样（每类挑一个代表），用于「全部试读」按钮。

    与 /env 的区别：不做电池与结论，只回答「这些传感器到底能不能读出数」。
    """
    try:
        names_all = _sensor_names()
    except Exception as e:                        # noqa: BLE001
        return _ok({'status': 'error', 'message': str(e)})
    try:
        frames = max(1, min(int(request.args.get('n') or 3), 20))
    except (TypeError, ValueError):
        frames = 3
    delay = 200
    raw = (request.args.get('s') or '').strip()
    if raw:
        _all, want, missing = _sensor_pick_list(raw)
    else:
        want, missing = [], []
        for n in names_all:
            if _kind_of(n) in ('system',):
                continue
            want.append(n)
            if len(want) >= MAX_SENSOR_PICK:
                break
    if not want:
        return _ok({'status': 'error', 'message': '没有可采样的传感器'}, 400)
    t0 = time.time()
    try:
        series = _sensor_collect(want, frames, delay)
    except Exception as e:                        # noqa: BLE001
        return _ok({'status': 'error', 'message': str(e)}, 500)
    ms = int((time.time() - t0) * 1000)
    rows = []
    for n in want:
        k, label, unit, group = _classify_sensor(n)
        rows.append({'name': n, 'kind': k, 'label': label, 'group': group,
                     'alive': bool(series.get(n)),
                     'channels': len(series.get(n)[-1]) if series.get(n) else 0,
                     'latest': series.get(n)[-1] if series.get(n) else []})
    return _ok({'rows': rows, 'elapsed_ms': ms, 'frames': frames,
                'alive': sum(1 for r in rows if r['alive']), 'total': len(rows),
                'missing': missing})

