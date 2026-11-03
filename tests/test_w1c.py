"""W1C checks use explicit hardware metadata and report read-modify-write risks."""

from types import SimpleNamespace

import pytest

from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l3_analysis.builtin_rules.rules_meta import get_rule_meta
from ecdet.l3_analysis.hw_model.checks_hw import HW_RULES
from ecdet.l3_analysis.hw_model.context import build_hw_context
from ecdet.l3_analysis.hw_model.svd import RegisterMap


RULE = "ECDET-MMIO-W1C"


def _run(statement: str, mask: int = 3, active: bool = True):
    source = (
        "#define GPIOA ((GPIO_TypeDef *)0x40000000)\n"
        "void test(void) {\n"
        f"  {statement}\n"
        "}\n"
    )
    context = finalize_facts([build_file_facts("w1c.c", source)])
    hw = build_hw_context(context)
    registers = {
        name: SimpleNamespace(
            name=name, peripheral="GPIOA", abs_addr=0x40000000 + offset,
            access="read-write", readable=True, writable=True,
            one_to_clear_mask=mask if name == "STATUS" else 0,
        )
        for name, offset in [("STATUS", 0), ("CTRL", 4)]
    }
    hw.regmap = RegisterMap(
        device="TEST", by_peripheral={"GPIOA": registers},
        periph_by_base={0x40000000: "GPIOA"},
    )
    return HW_RULES[RULE](context, hw, {RULE} if active else set())


@pytest.mark.parametrize("statement", [
    "GPIOA->STATUS |= FLAG_A;",
    "GPIOA->STATUS &= ~FLAG_A;",
    "GPIOA->STATUS ^= FLAG_A;",
    "GPIOA->STATUS += 1u;",
    "GPIOA->STATUS -= 1u;",
    "GPIOA->STATUS <<= 1u;",
    "GPIOA->STATUS >>= 1u;",
    "GPIOA->STATUS++;",
    "--GPIOA->STATUS;",
    "(GPIOA->STATUS) |= FLAG_A;",
    "GPIOA->STATUS = GPIOA->STATUS | FLAG_A;",
    "GPIOA->STATUS = (GPIOA->STATUS & ~FLAG_A);",
    "GPIOA->STATUS = (FLAG_A) & GPIOA->STATUS;",
    "GPIOA->STATUS = ((FLAG_A)) & GPIOA->STATUS;",
    "GPIOA->STATUS = read_flag(GPIOA->STATUS);",
    "GPIOA->STATUS =\n GPIOA->STATUS | FLAG_A;",
    "*(volatile unsigned int *)0x40000000 |= FLAG_A;",
    "(*(volatile unsigned int *)0x40000000)++;",
    "++(*(volatile unsigned int *)(0x40000000));",
    "*(volatile unsigned int *)0x40000000 = *(volatile unsigned int *)0x40000000 | FLAG_A;",
    "GPIOA->STATUS = *(volatile unsigned int *)0x40000000 | FLAG_A;",
])
def test_w1c_read_modify_write_warns(statement):
    alerts = _run(statement)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == RULE and alert.severity.value == "warning"
    assert alert.location.path == "w1c.c" and alert.location.line == 3
    assert "写1清零" in alert.message
    assert any("0x40000000" in evidence.message and "0x00000003" in evidence.message
               for evidence in alert.evidence)


@pytest.mark.parametrize("statement", [
    "GPIOA->STATUS = FLAG_A;",
    "GPIOA->STATUS = 0u;",
    "unsigned int flags = GPIOA->STATUS;",
    "GPIOA->CTRL |= FLAG_A;",
    "UNKNOWN->STATUS |= FLAG_A;",
    "GPIOA->STATUS = GPIOA->CTRL | FLAG_A;",
    "GPIOA->STATUS = FLAG_A; unsigned int flags = GPIOA->STATUS;",
    "GPIOA->STATUS = sizeof(GPIOA->STATUS);",
    "GPIOA->STATUS = (unsigned int)&GPIOA->STATUS;",
    "GPIOA->STATUS = (uint32_t)&GPIOA->STATUS;",
    "int equal = (GPIOA->STATUS == GPIOA->STATUS);",
    "// GPIOA->STATUS |= FLAG_A;",
    'const char *message = "GPIOA->STATUS |= FLAG_A;";',
    "*(volatile unsigned int *)0x40000001 |= FLAG_A;",
    "if (GPIOA->STATUS) ++flag;",
    "while (GPIOA->STATUS) --flag;",
    "read_flag(GPIOA->STATUS); ++flag;",
    "unsigned int length = sizeof(GPIOA->STATUS++);",
    "unsigned int length = sizeof GPIOA->STATUS++;",
    "unsigned int length = sizeof(*(volatile unsigned int *)0x40000000 |= FLAG_A);",
])
def test_w1c_safe_or_unresolved_operations_do_not_warn(statement):
    assert _run(statement) == []


def test_w1c_requires_metadata_and_enabled_rule():
    assert _run("GPIOA->STATUS |= FLAG_A;", mask=0) == []
    assert _run("GPIOA->STATUS |= FLAG_A;", active=False) == []


def test_w1c_rule_metadata_is_registered():
    meta = get_rule_meta(RULE)
    assert meta is not None and "写1清零" in meta.title_zh
