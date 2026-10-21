"""执行载体三级吞吐-保真梯度（方案 3.3.5 之执行载体分层）。

宿主机原生执行（HostCarrier，嵌入式 Linux 目标档）→ Unicorn CPU 级
仿真（单固件快速 fuzzing 档）→ Renode 外设级仿真（多节点/外设模型档）。
探测到即接入：Unicorn 以 python 包存在为准，Renode 以 renode 二进制
为准；未安装的载体 available=False，引擎自动降级到下一档并留痕。
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from ecdet.l3_analysis.builtin_rules.checks import FileFacts


@dataclass
class CarrierContext:
    root: Path
    workdir: Path
    include_dirs: list[Path]
    facts: list[FileFacts]


@dataclass
class CarrierInfo:
    name: str
    tier: int                  # 1 宿主（最高吞吐）→ 3 Renode（最高保真）
    available: bool
    note: str = ""


class HostCarrier:
    """宿主机原生执行：gcc 编译 + 直接运行（当前实现，见 engine.py）。"""

    name = "host"
    tier = 1

    @staticmethod
    def available() -> bool:
        return shutil.which("gcc") is not None

    @staticmethod
    def info() -> CarrierInfo:
        return CarrierInfo(HostCarrier.name, HostCarrier.tier,
                           HostCarrier.available(),
                           "" if HostCarrier.available() else "gcc 不可用")


class UnicornCarrier:
    """Unicorn CPU 级仿真：轻量、启动快，适合单固件镜像快速 fuzzing。

    接入要求：python 包 `unicorn`（pip install unicorn）+ 固件镜像
    与加载地址元数据。MVP 仅做可用性探测与降级留痕，执行回路待
    固件镜像语料接入后启用（方案阶段四后半）。
    """

    name = "unicorn"
    tier = 2

    @staticmethod
    def available() -> bool:
        try:
            import unicorn  # noqa: F401
            return True
        except ImportError:
            return False

    @staticmethod
    def info() -> CarrierInfo:
        note = "" if UnicornCarrier.available() else \
            "未安装 python 包 unicorn（pip install unicorn）"
        return CarrierInfo(UnicornCarrier.name, UnicornCarrier.tier,
                           UnicornCarrier.available(), note)


class RenodeCarrier:
    """Renode 外设级仿真：多节点与外设模型，保真度最高档。

    接入要求：renode 二进制（PATH）+ .resc 平台描述脚本。
    MVP 仅做可用性探测与降级留痕。
    """

    name = "renode"
    tier = 3

    @staticmethod
    def available() -> bool:
        return shutil.which("renode") is not None

    @staticmethod
    def info() -> CarrierInfo:
        note = "" if RenodeCarrier.available() else \
            "未安装 renode 二进制（https://renode.io）"
        return CarrierInfo(RenodeCarrier.name, RenodeCarrier.tier,
                           RenodeCarrier.available(), note)


ALL_CARRIERS = [HostCarrier, UnicornCarrier, RenodeCarrier]


def probe_carriers() -> list[CarrierInfo]:
    """探测全部载体（编排层日志与 PoC 报告披露用）。"""
    return [c.info() for c in ALL_CARRIERS]


def pick_carrier(preferred: str | None = None) -> tuple[type, CarrierInfo | None]:
    """按吞吐-保真梯度选载体：显式指定优先，否则取最高吞吐的可用档。"""
    if preferred:
        for c in ALL_CARRIERS:
            if c.name == preferred:
                info = c.info()
                return (c, info) if info.available else (None, info)
        return None, None
    for c in ALL_CARRIERS:
        info = c.info()
        if info.available:
            return c, info
    return None, None
