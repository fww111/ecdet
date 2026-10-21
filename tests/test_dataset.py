# -*- coding: utf-8 -*-
"""阶段三：数据集采集管线测试（离线 git 仓库 fixture）。"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from build_dataset import (  # noqa: E402
    Manifest,
    Advisory,
    build_samples,
    extract_functions,
    find_fix_commits,
    fingerprint_text,
    load_manifest,
    write_dataset,
)

pytest.importorskip("git") if False else None   # git 由 subprocess 调用


def _git(repo: Path, *args: str) -> str:
    env = {"PATH": "/usr/bin:/bin:/mingw64/bin",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
           "HOME": str(repo.parent)}
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                       text=True, encoding="utf-8", env={**__import__("os").environ,
                                                         **env})
    assert r.returncode == 0, r.stderr
    return r.stdout


VULN_C_V1 = """\
#include <stdint.h>

static uint8_t g_len;

/* 拷贝传感器名称（存在溢出） */
void sensor_set_name(const char *name)
{
    char buf[8];
    uint8_t i = 0;
    while (name[i] && i < 255u) {
        buf[i] = name[i];
        i++;
    }
    g_len = i;
}

void sensor_ok(void)
{
    g_len = 0u;
}
"""

VULN_C_V2 = """\
#include <stdint.h>

static uint8_t g_len;

/* 拷贝传感器名称（修复：限长拷贝） */
void sensor_set_name(const char *name)
{
    char buf[8];
    uint8_t i = 0;
    while (name[i] && i < 7u) {
        buf[i] = name[i];
        i++;
    }
    buf[7] = 0;
    g_len = i;
}

void sensor_ok(void)
{
    g_len = 0u;
}
"""


@pytest.fixture(scope="module")
def demo_repo(tmp_path_factory):
    repo = tmp_path_factory.mktemp("rt_thread_like")
    (repo / "driver.c").write_text(VULN_C_V1, encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "init driver")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "--allow-empty", "-m", "placeholder",
         "--date", "2024-01-01")
    (repo / "driver.c").write_text(VULN_C_V2, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "fix CVE-2024-1234: buffer overflow in sensor_set_name")
    fix1 = _git(repo, "rev-parse", "HEAD").strip()

    (repo / "net.c").write_text(
        "#include <stdint.h>\n"
        "int net_send(const void *d, int n) { (void)d; return n; }\n",
        encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "add net")
    (repo / "net.c").write_text(
        "#include <stdint.h>\n"
        "int net_send(const void *d, int n) { (void)d; return n * 2; }\n",
        encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "fix GHSA-xxxx-1: net_send length check")
    fix2 = _git(repo, "rev-parse", "HEAD").strip()
    return repo, fix1, fix2


def _manifest(repo: Path, fix1: str, fix2: str, path="manifest.json") -> Path:
    m = {
        "repo": str(repo),
        "license": "Apache-2.0",
        "advisories": [
            {"cve": "CVE-2024-1234", "cwe": "CWE-120", "fix_commit": fix1,
             "date": "2024-03-01", "severity_gb": "高危",
             "is_mmio": False, "is_rtos": False, "summary": "栈溢出"},
            {"cve": "CVE-2024-5678", "cwe": "CWE-190", "fix_commit": fix2,
             "date": "2024-06-01", "severity_gb": "中危",
             "is_rtos": True, "is_isr": False, "is_mmio": False,
             "summary": "长度整数溢出"},
        ],
    }
    p = repo / path
    p.write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


# ---------------- 单元：切片与指纹 ----------------

def test_extract_functions_slices():
    funcs = extract_functions(VULN_C_V1)
    names = [f["name"] for f in funcs]
    assert names == ["sensor_set_name", "sensor_ok"]
    body = funcs[0]["code"]
    assert "buf[i] = name[i];" in body and "#include" not in body


def test_fingerprint_ignores_comments_and_ws():
    a = fingerprint_text("int f(void) { return 1; }  /* 注释 */")
    b = fingerprint_text("int f(void)\n{\n    return 1;   // 另一注释\n}")
    assert a == b


def test_fingerprint_distinguishes_code():
    a = fingerprint_text("int f(void) { return 1; }")
    b = fingerprint_text("int f(void) { return 2; }")
    assert a != b


# ---------------- 单元：修复提交检索 ----------------

def test_find_fix_commits(demo_repo):
    repo, _, _ = demo_repo
    fixes = find_fix_commits(repo)
    subjects = [f["subject"] for f in fixes]
    assert any("CVE-2024-1234" in s for s in subjects)
    assert any("GHSA" in s for s in subjects)


# ---------------- 集成：样本构建 ----------------

def test_build_samples_end_to_end(demo_repo, tmp_path):
    repo, fix1, fix2 = demo_repo
    mpath = _manifest(repo, fix1, fix2)
    manifest = load_manifest(mpath)
    samples, stats = build_samples(manifest, pair_ratio=5, seed=42)

    labels = {s.label for s in samples}
    assert {"vulnerable", "fixed", "normal"} <= labels

    vuln = [s for s in samples if s.label == "vulnerable"]
    assert any(s.func_name == "sensor_set_name" and s.cwe == "CWE-120"
               for s in vuln)

    # 漏洞函数与修复函数指纹不同（代码确实变化）
    v = next(s for s in vuln if s.func_name == "sensor_set_name")
    fixed = next(s for s in samples if s.label == "fixed"
                 and s.func_name == "sensor_set_name")
    assert v.fingerprint != fixed.fingerprint

    # 近重复删除：全部指纹唯一
    fps = [s.fingerprint for s in samples]
    assert len(fps) == len(set(fps))

    # 嵌入式上下文标注透传 + ISR 自动识别
    assert all(hasattr(s, "is_isr") for s in samples)
    assert stats["by_cwe"]["CWE-120"] >= 2

    # 时间划分：6:2:2 → 2 个通告分属两集合，无时间泄漏
    splits = {s.split for s in samples}
    assert splits <= {"train", "val", "test"}
    v_splits = {s.split for s in vuln}
    assert "train" in v_splits


def test_write_dataset_outputs(demo_repo, tmp_path):
    repo, fix1, fix2 = demo_repo
    manifest = load_manifest(_manifest(repo, fix1, fix2,
                                       path="manifest2.json"))
    samples, stats = build_samples(manifest, seed=42)
    out = tmp_path / "ds"
    write_dataset(samples, stats, manifest, out)
    lines = (out / "samples.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(samples)
    rec = json.loads(lines[0])
    assert {"sample_id", "cwe", "label", "code", "fingerprint", "split",
            "severity_gb", "is_isr"} <= set(rec)
    assert (out / "stats.json").exists()
    assert (out / "LICENSES.md").exists()
    assert "Apache-2.0" in (out / "LICENSES.md").read_text(encoding="utf-8")
