import asyncio
import websockets

async def connect_and_communicate():
    uri = "wss://screeps.com/socket/826/ddvh09o4/websocket"
    async with websockets.connect(uri) as websocket:
        # 发送信息到服务器
        message = '["auth 9b280507451a4b52a82144a5ef2f5620763ce622"]'
        await websocket.send(message)
        print(f"发送: {message}")

        # 接收服务器返回的数据
        response = await websocket.recv()
        print(f"接收: {response}")

# 运行异步函数
asyncio.run(connect_and_communicate())
