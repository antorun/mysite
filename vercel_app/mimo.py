"""小米 MiMo API 客户端（支持流式 SSE 解析与转发）

将 MiMo 的 SSE 响应解析为标准文本增量，供 Flask 接口以流式方式回传给前端。
鉴权 Cookie 来自会话，注意 serviceToken 会过期，过期后需更新下方常量
（或注入环境变量 MIMO_SERVICE_TOKEN / MIMO_USER_ID / MIMO_PH 覆盖）。
"""
import json
import uuid

import requests


# ---- MiMo API 配置 ----
MIMO_URL = "https://aistudio.xiaomimimo.com/open-apis/bot/chat"

# 优先读环境变量，便于在不改代码的情况下轮换凭证
import os

MIMO_PH = os.environ.get("MIMO_PH", "")
MIMO_USER_ID = os.environ.get("MIMO_USER_ID", "")
MIMO_SERVICE_TOKEN = os.environ.get("MIMO_SERVICE_TOKEN", "")

_HEADERS = {
    "content-type": "application/json",
    "origin": "https://aistudio.xiaomimimo.com",
    "referer": "https://aistudio.xiaomimimo.com/",
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/150.0.0.0 Safari/537.36"
    ),
    "accept": "*/*",
    "accept-language": "system",
    "accept-encoding": "gzip, deflate, br, zstd",
    "x-timezone": "Asia/Shanghai",
    "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "priority": "u=1, i",
}

_COOKIES = {
    "userId": MIMO_USER_ID,
    "serviceToken": MIMO_SERVICE_TOKEN,
    "xiaomichatbot_ph": MIMO_PH,
}


def _build_body(query, conversation_id, msg_id, enable_thinking):
    """构造请求体，conversation_id / msg_id 未提供时自动生成"""
    return {
        "msgId": msg_id or uuid.uuid4().hex,
        "conversationId": conversation_id or uuid.uuid4().hex,
        "query": query,
        "isEditedQuery": False,
        "modelConfig": {
            "enableThinking": bool(enable_thinking),
            "webSearchStatus": "disabled",
            "model": "mimo-v2.5-pro",
        },
        "multiMedias": [],
    }


def _find_any(s, markers, start):
    """在 s[start:] 中查找最早出现的标记，返回 (index, marker) 或 None"""
    best = None
    for m in markers:
        idx = s.find(m, start)
        if idx != -1 and (best is None or idx < best[0]):
            best = (idx, m)
    return best


def _split_think_stream(content, ctx):
    """增量地将文本块拆分为 (reasoning, answer) 两部分。

    ctx: {'in_think': bool} 跨块状态字典（会就地更新）。
    同时兼容两种写法：原始标签 <think>/</think> 与 HTML 实体 &lt;think&gt;/&lt;/think&gt;。
    返回 (reasoning_text, answer_text)，未命中的部分为空串。
    """
    reasoning_parts = []
    answer_parts = []
    i = 0
    n = len(content)
    OPEN = ('<think>', '&lt;think&gt;')
    CLOSE = ('</think>', '&lt;/think&gt;')
    while i < n:
        if ctx['in_think']:
            close = _find_any(content, CLOSE, i)
            if close is None:
                reasoning_parts.append(content[i:])  # 整块都在思考区
                i = n
            else:
                ci, cm = close
                reasoning_parts.append(content[i:ci])
                i = ci + len(cm)
                ctx['in_think'] = False
        else:
            open_m = _find_any(content, OPEN, i)
            if open_m is None:
                answer_parts.append(content[i:])
                i = n
            else:
                oi, om = open_m
                answer_parts.append(content[i:oi])  # 标记前的正文
                i = oi + len(om)
                ctx['in_think'] = True
    return ''.join(reasoning_parts), ''.join(answer_parts)


def stream_chat(query, conversation_id="", msg_id="", enable_thinking=False):
    """流式调用 MiMo，逐块 yield (kind, text) 元组。

    Yields:
        tuple: ('content', str) 正文增量；或 ('reasoning', str) 思考过程增量
               （仅当 enable_thinking=True 时才会产出 reasoning）

    Raises:
        requests.HTTPError / requests.Timeout: 由调用方（接口层）捕获处理
    """
    if not (MIMO_PH and MIMO_USER_ID and MIMO_SERVICE_TOKEN):
        raise RuntimeError("MiMo 凭证未配置（需设置 MIMO_PH / MIMO_USER_ID / MIMO_SERVICE_TOKEN）")

    body = _build_body(query, conversation_id, msg_id, enable_thinking)

    resp = requests.post(
        MIMO_URL,
        params={"xiaomichatbot_ph": MIMO_PH},
        headers=_HEADERS,
        cookies=_COOKIES,
        json=body,
        stream=True,
        timeout=(15, 180),
    )
    resp.raise_for_status()
    resp.encoding = "utf-8"  # 强制 UTF-8，修复中文乱码

    think_ctx = {'in_think': False}

    for line in resp.iter_lines(decode_unicode=True):
        if not line:
            continue
        if not line.startswith("data:"):
            continue  # 跳过 event: 等行

        raw = line[len("data:"):].strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        if data.get("type") != "text":
            continue

        content = data.get("content", "")
        if not content:
            continue
        # 去除 MiMo 偶发的前导 NUL 控制字符（\x00），避免污染输出
        content = content.replace('\x00', '')

        reasoning, answer = _split_think_stream(content, think_ctx)
        if enable_thinking and reasoning:
            yield ('reasoning', reasoning)
        if answer:
            yield ('content', answer)
