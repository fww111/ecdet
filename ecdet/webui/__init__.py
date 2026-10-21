"""Web 控制台（零第三方依赖：stdlib HTTP 服务 + SQLite + 单页前端）。

工程输入三源归一（详见 README）：
  本地路径（零拷贝） / 上传 zip（解压入工作区） / Git 地址（浅克隆）
  → Project 注册 → Run 后台队列执行（复用 L1→L5 流水线）
  → 告警入库 → 浏览/筛选/人工复核状态流转。
"""

from ecdet.webui.store import Store
from ecdet.webui.server import WebUI

__all__ = ["Store", "WebUI"]
