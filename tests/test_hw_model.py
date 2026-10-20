# -*- coding: utf-8 -*-
"""阶段二：SVD 解析 / 硬件语义检查 / ISR 识别测试。"""

import textwrap
from pathlib import Path

from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l3_analysis.hw_model.context import build_hw_context, fold_expr, resolve_base_address
from ecdet.l3_analysis.hw_model.checks_hw import HW_RULES
from ecdet.l3_analysis.hw_model.svd import parse_svd

SVD = """<?xml version="1.0"?>
<device>
  <name>TEST32F1</name>
  <peripherals>
    <peripheral>
      <name>GPIOA</name>
      <baseAddress>0x40020000</baseAddress>
      <registers>
        <register><name>MODER</name><addressOffset>0x00</addressOffset><access>read-write</access></register>
        <register><name>IDR</name><addressOffset>0x10</addressOffset><access>read-only</access></register>
        <register><name>BSRR</name><addressOffset>0x18</addressOffset><access>write-only</access></register>
      </registers>
    </peripheral>
  </peripherals>
</device>
"""


def _run(src: str, tmp_path: Path, with_svd: bool = True):
    src = textwrap.dedent(src)
    root = tmp_path / "proj"
    root.mkdir(exist_ok=True)
    svd = None
    if with_svd:
        svd = root / "chip.svd"
        svd.write_text(SVD, encoding="utf-8")
    facts = [build_file_facts("t.c", src)]
    ctx = finalize_facts(facts)
    hw = build_hw_context(ctx, svd)
    alerts = []
    groups: dict = {}
    for rid, fn in HW_RULES.items():
        groups.setdefault(fn, set()).add(rid)
    for fn, rids in groups.items():
        alerts.extend(fn(ctx, hw, rids))
    return alerts, hw


# ---------------- SVD 解析 ----------------

def test_parse_svd(tmp_path):
    p = tmp_path / "chip.svd"
    p.write_text(SVD, encoding="utf-8")
    rm = parse_svd(p)
    assert rm.device == "TEST32F1"
    idr = rm.resolve("GPIOA", "IDR")
    assert idr is not None
    assert idr.abs_addr == 0x40020010
    assert idr.readable and not idr.writable
    bsrr = rm.resolve("gpioa", "bsrr")       # 大小写不敏感
    assert bsrr is not None and not bsrr.readable and bsrr.writable
    assert rm.lookup(0x40020013) is not None  # 未对齐退化匹配


# ---------------- 宏折叠与基址解析 ----------------

def test_fold_expr(tmp_path):
    bodies = {
        "PERIPH_BASE": "0x40000000UL",
        "GPIOA_BASE": "(PERIPH_BASE + 0x00020000UL)",
        "MASK": "(1u << 3)",
    }
    assert fold_expr("PERIPH_BASE", bodies) == 0x40000000
    assert fold_expr("GPIOA_BASE", bodies) == 0x40020000
    assert fold_expr("MASK", bodies) == 8
    assert fold_expr("(2 + 3) * 4", bodies) == 20
    assert fold_expr("UNKNOWN_X + 1", bodies) is None


# ---------------- MMIO 权限检查 ----------------

def test_mmio_ro_write(tmp_path):
    src = """
    #define GPIOA ((GPIO_TypeDef *) 0x40020000)
    void f(void) { GPIOA->IDR = 1u; }
    """
    alerts, _ = _run(src, tmp_path)
    mmio = [a for a in alerts if a.rule_id == "ECDET-MMIO-ACCESS"]
    assert len(mmio) == 1
    assert mmio[0].severity.value == "error"
    assert "只读" in mmio[0].message


def test_mmio_wo_read(tmp_path):
    src = """
    #define GPIOA ((GPIO_TypeDef *) 0x40020000)
    int f(void) { int x = 0; x |= GPIOA->BSRR; return x; }
    """
    alerts, _ = _run(src, tmp_path)
    mmio = [a for a in alerts if a.rule_id == "ECDET-MMIO-ACCESS"]
    assert len(mmio) == 1
    assert mmio[0].severity.value == "warning"
    assert "只写" in mmio[0].message


def test_mmio_rw_ok(tmp_path):
    src = """
    #define GPIOA ((GPIO_TypeDef *) 0x40020000)
    void f(void) { GPIOA->MODER = 1u; }
    """
    alerts, _ = _run(src, tmp_path)
    assert [a for a in alerts if a.rule_id == "ECDET-MMIO-ACCESS"] == []


def test_mmio_macro_arith_base(tmp_path):
    """两级宏展开的基址（PERIPH_BASE + offset）也能解析。"""
    src = """
    #define PERIPH_BASE 0x40000000UL
    #define GPIOA_BASE  (PERIPH_BASE + 0x00020000UL)
    #define GPIOA       ((GPIO_TypeDef *) GPIOA_BASE)
    void f(void) { GPIOA->IDR = 1u; }
    """
    alerts, hw = _run(src, tmp_path)
    assert resolve_base_address("GPIOA", hw) == 0x40020000
    mmio = [a for a in alerts if a.rule_id == "ECDET-MMIO-ACCESS"]
    assert len(mmio) == 1


def test_mmio_direct_address(tmp_path):
    src = "void f(void) { *(volatile unsigned int *)0x40020010 = 0u; }"
    alerts, _ = _run(src, tmp_path)
    mmio = [a for a in alerts if a.rule_id == "ECDET-MMIO-ACCESS"]
    assert len(mmio) == 1 and "只读" in mmio[0].message


def test_mmio_no_svd_skipped(tmp_path):
    src = "void f(void) { GPIOA->IDR = 1u; }"
    alerts, hw = _run(src, tmp_path, with_svd=False)
    assert hw.regmap is None
    assert [a for a in alerts if a.rule_id == "ECDET-MMIO-ACCESS"] == []


# ---------------- ISR 识别与竞争检查 ----------------

def test_isr_race_and_volatile(tmp_path):
    src = """
    volatile uint32_t g_rx;
    uint32_t g_ctrl;

    void USART1_IRQHandler(void) { g_rx = 1u; g_ctrl = 1u; }

    void task(void) {
        taskENTER_CRITICAL();
        (void)g_rx;          /* 临界区内：受保护 */
        taskEXIT_CRITICAL();
        (void)g_ctrl;        /* 区间外：无保护 */
    }
    """
    alerts, hw = _run(src, tmp_path, with_svd=False)
    assert "USART1_IRQHandler" in hw.isr_names
    races = [a for a in alerts if a.rule_id == "ECDET-ISR-RACE"]
    vols = [a for a in alerts if a.rule_id == "ECDET-VOLATILE"]
    assert len(races) == 1 and "g_ctrl" in races[0].message
    assert "g_rx" not in races[0].message          # 受保护的不报
    assert len(vols) == 1 and "g_ctrl" in vols[0].message


def test_isr_race_volatile_var_no_volatile_alert(tmp_path):
    src = """
    volatile uint32_t g_v;
    void TIM3_IRQHandler(void) { g_v++; }
    void task(void) { (void)g_v; }
    """
    alerts, _ = _run(src, tmp_path, with_svd=False)
    assert [a for a in alerts if a.rule_id == "ECDET-VOLATILE"] == []


def test_isr_blocking(tmp_path):
    src = """
    void TIM2_IRQHandler(void) { vTaskDelay(1); }
    void task(void) { vTaskDelay(1); }          /* 任务上下文合法 */
    """
    alerts, _ = _run(src, tmp_path, with_svd=False)
    blocks = [a for a in alerts if a.rule_id == "ECDET-ISR-BLOCK"]
    assert len(blocks) == 1
    assert "TIM2_IRQHandler" in blocks[0].message
    assert "vTaskDelay" in blocks[0].message


def test_isr_fromisr_variant_hint(tmp_path):
    src = """
    void UART4_IRQHandler(void) { xQueueSend(0, 0, 0); }
    """
    alerts, _ = _run(src, tmp_path, with_svd=False)
    blocks = [a for a in alerts if a.rule_id == "ECDET-ISR-BLOCK"]
    assert len(blocks) == 1
    assert "xQueueSendFromISR" in blocks[0].message


def test_vector_table_isr_identified(tmp_path):
    """启动文件向量表中的函数也应被识别为 ISR。"""
    startup = """
    void WWDG_IRQHandler(void) { }
    const void *vectors[] = { WWDG_IRQHandler, 0 };
    """
    facts = [build_file_facts("startup.c", textwrap.dedent(startup))]
    ctx = finalize_facts(facts)
    hw = build_hw_context(ctx, None)
    assert "WWDG_IRQHandler" in hw.isr_names
