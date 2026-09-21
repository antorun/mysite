"""
Vercel Serverless Function 入口 — 转发到 Flask 应用
"""
import os
import sys

# 将项目根目录加入 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vercel_app.app import app
