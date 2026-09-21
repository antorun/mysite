# server.py
import asyncio
import websockets
import json

# 存储所有连接的客户端
connected_clients = set()

async def handler(websocket, path):
    # 将新连接的客户端添加到集合中
    connected_clients.add(websocket)
    print("Client connected")

    try:
        async for message in websocket:
            # 打印接收到的消息到终端
            print(f"Received message: {message}")
            
            # 广播消息给所有连接的客户端
            await asyncio.wait([client.send(message) for client in connected_clients if client != websocket])
    except websockets.exceptions.ConnectionClosedOK:
        print("Client disconnected")
    except websockets.exceptions.ConnectionClosedError:
        print("Client disconnected with error")
    finally:
        # 从集合中移除断开的客户端
        connected_clients.remove(websocket)

async def main():
    async with websockets.serve(handler, "0.0.0.0", 8080):
        print("WebSocket server is running on ws://0.0.0.0:8080")
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())