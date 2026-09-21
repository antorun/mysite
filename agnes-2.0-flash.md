# Agnes 2.0 Flash - 使用文档

> Sapiens AI 出品 | 256K 上下文 | 支持多模态/工具调用/智能体

---

## 基本信息

| 项目 | 值 |
|------|-----|
| **模型 ID** | `agnes-2.0-flash` |
| **API 地址** | `https://apihub.agnes-ai.com/v1` |
| **API Key** | `sk-StrFu7JzpCMr2hP2Cs07baTNIalYUdLQ292SoUU3XF0vRRbC` |
| **上下文长度** | 256K tokens |
| **Max Tokens 上限** | 65,536 (65.5K) |
| **接口兼容** | OpenAI API 格式 |

---

## 支持的模型家族

| 模型 ID | 类型 | 说明 |
|---------|------|------|
| `agnes-2.0-flash` | 文本对话 | 默认聊天模型，支持图片理解、工具调用、Agent |
| `agnes-image-2.1-flash` | 图片生成 | 文生图 / 图生图 |
| `agnes-video-v2.0` | 视频生成 | 文生视频 / 图生视频 |

> 三个模型共用同一个 API 地址和 API Key。

---

## 文本对话调用

**请求地址**: `POST https://apihub.agnes-ai.com/v1/chat/completions`

### 基础调用

```python
import requests

API_URL = "https://apihub.agnes-ai.com/v1"
API_KEY = "sk-StrFu7JzpCMr2hP2Cs07baTNIalYUdLQ292SoUU3XF0vRRbC"

payload = {
    "model": "agnes-2.0-flash",
    "messages": [
        {"role": "user", "content": "你好，请介绍一下你自己"}
    ],
    "temperature": 0.7,
    "max_tokens": 4096,
    "stream": False
}

resp = requests.post(
    f"{API_URL}/chat/completions",
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    },
    json=payload
)

data = resp.json()
print(data["choices"][0]["message"]["content"])
```

### 多模态（图片理解）

```python
payload = {
    "model": "agnes-2.0-flash",
    "messages": [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "这张图片里有什么？"},
                {"type": "image_url", "image_url": {"url": "https://example.com/photo.jpg"}}
            ]
        }
    ],
    "temperature": 0.7,
    "max_tokens": 4096
}
```

> 图片支持 URL 或 base64 格式。

### 启用 Thinking 模式（编码/推理/Agent 任务推荐）

```python
payload = {
    "model": "agnes-2.0-flash",
    "messages": [...],
    "chat_template_kwargs": {
        "enable_thinking": True
    }
}
```

---

## 图片生成调用

**请求地址**: `POST https://apihub.agnes-ai.com/v1/images/generations`

### 文生图

```python
payload = {
    "model": "agnes-image-2.1-flash",
    "prompt": "一只可爱的橘猫坐在窗台上，阳光洒在身上",
    "size": "1024x768",
    "extra_body": {
        "response_format": "url"
    }
}

resp = requests.post(
    f"{API_URL}/images/generations",
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    },
    json=payload
)

data = resp.json()
image_url = data["data"][0]["url"]
print(f"生成图片: {image_url}")
```

### 图生图（带参考图片）

```python
payload = {
    "model": "agnes-image-2.1-flash",
    "prompt": "把这张照片改成油画风格",
    "size": "1024x768",
    "extra_body": {
        "response_format": "url",
        "image": ["data:image/jpeg;base64,/9j/4AAQ..."]  # 参考图片 base64
    }
}
```

---

## 视频生成调用（异步任务）

视频生成是异步的：先创建任务，再轮询查询结果。

### 1. 创建视频任务

**请求地址**: `POST https://apihub.agnes-ai.com/v1/videos`

```python
payload = {
    "model": "agnes-video-v2.0",
    "prompt": "一只蝴蝶在花园里飞舞",
    "num_frames": 121,       # 帧数
    "frame_rate": 24         # 帧率
}

resp = requests.post(
    f"{API_URL}/videos",
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    },
    json=payload
)

data = resp.json()
video_id = data["video_id"]  # 保存此 ID 用于查询
```

### 图生视频（带参考图片）

```python
payload = {
    "model": "agnes-video-v2.0",
    "prompt": "让这张图片动起来",
    "image": "data:image/jpeg;base64,/9j/4AAQ...",  # 参考图片 base64
    "num_frames": 121,
    "frame_rate": 24
}
```

### 2. 轮询查询视频结果

```python
import time

# 注意查询地址不是 v1 路径
query_url = "https://apihub.agnes-ai.com/agnesapi?video_id=" + video_id

for _ in range(60):  # 最多等 10 分钟
    time.sleep(10)

    resp = requests.get(query_url, headers={
        "Authorization": f"Bearer {API_KEY}"
    })
    data = resp.json()
    status = data.get("status")

    if status == "completed":
        video_url = data["remixed_from_video_id"]
        print(f"视频已生成: {video_url}")
        print(f"时长: {data.get('seconds')}s, 分辨率: {data.get('size')}")
        break
    elif status == "failed":
        print(f"生成失败: {data.get('error', {}).get('message', '未知错误')}")
        break
    else:
        print(f"状态: {status}, 进度: {data.get('progress', 0)}%")
```

> **注意**: 视频查询端点为 `https://apihub.agnes-ai.com/agnesapi`，不是 `/v1/agnesapi`。

---

## 前端项目中使用方式

你的 `ai_chat.html` 中已经内嵌了完整的调用代码。关键配置：

```javascript
// 默认模型列表（硬编码在 js 中）
const defaultModels = [
    {
        id: "agnes-2.0-flash",
        name: "Agnes 2.0 Flash",
        desc: "Sapiens AI · 256K上下文 · 支持图片/工具调用/智能体",
        apiUrl: "https://apihub.agnes-ai.com/v1",
        apiKey: "sk-StrFu7JzpCMr2hP2Cs07baTNIalYUdLQ292SoUU3XF0vRRbC",
        type: "chat"
    }
];
```

> **安全建议**: API Key 当前硬编码在前端 JS 中，所有用户都能看到。建议将 Key 放在后端做代理转发，或限制 Key 的使用权限。

---

## 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `temperature` | 0.7 | 随机性 (0-2) |
| `max_tokens` | 4096 | 最大输出 token (Agnes 最大 65500) |
| `top_p` | 未指定 (不走后端) | 采样参数 |
| `stream` | false | 是否流式输出 |
| `enable_thinking` | false | 是否启用深度思考模式 |
| `system_prompt` | "你是一个有帮助的AI助手" | 系统提示词 |

---

## 注意事项

1. **API Key 安全**: 前端硬编码的 Key 任何人都能获取，**不建议在生产环境这样使用**
2. **max_tokens 上限**: Agnes 2.0 Flash 最大支持 65,536 tokens 输出
3. **图片格式**: 支持 base64 和 URL 两种方式传入图片
4. **视频生成**: 是异步任务，需要轮询结果，大约需要 1-10 分钟
5. **查询端点**: 视频查询是 `/agnesapi` 而不是 `/v1/agnesapi`，注意路径
