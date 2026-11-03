"""SVD expansion, field semantics and explicit degraded-state regressions."""
import builtins
from pathlib import Path

import pytest

from ecdet.l3_analysis.hw_model.svd import parse_svd
from ecdet.l3_analysis.hw_model.context import build_hw_context
from ecdet.l3_analysis.builtin_rules.checks import finalize_facts

SIMPLE = '''<device><name>TEST</name><size>16</size><access>read-write</access>
<peripherals><peripheral><name>gpio</name><baseAddress>0x40000000</baseAddress>
<registers><register><name>status</name><addressOffset>0</addressOffset>
<modifiedWriteValues>oneToClear</modifiedWriteValues><fields>
<field><name>A</name><bitOffset>0</bitOffset><bitWidth>1</bitWidth></field>
<field><name>B</name><bitRange>[3:2]</bitRange><access>read-only</access></field>
<field><name>C</name><lsb>4</lsb><msb>5</msb><modifiedWriteValues>modify</modifiedWriteValues></field>
</fields></register></registers></peripheral></peripherals></device>'''

def write(tmp_path, content=SIMPLE):
    path = tmp_path / 'chip.svd'
    path.write_text(content, encoding='utf-8')
    return path

def without_cmsis(monkeypatch):
    original = builtins.__import__
    def importing(name, *args, **kwargs):
        if name == 'cmsis_svd.parser':
            raise ModuleNotFoundError("No module named 'cmsis_svd'", name='cmsis_svd')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', importing)

@pytest.mark.parametrize('backend', ['builtin', 'cmsis-svd'])
def test_field_metadata_and_write_mask(tmp_path, backend):
    if backend == 'cmsis-svd':
        pytest.importorskip('cmsis_svd')
    rm = parse_svd(write(tmp_path), backend=backend)
    reg = rm.resolve('GPIO', 'STATUS')
    assert rm.parser_backend == backend
    assert reg.size == 16
    assert [(f.name, f.bit_offset, f.bit_width) for f in reg.fields] == [('A',0,1),('B',2,2),('C',4,2)]
    assert not reg.fields[1].writable
    assert reg.one_to_clear_mask == 0xFFFF & ~0x3C

def test_optional_dependency_fallback_is_visible(tmp_path, monkeypatch, caplog):
    without_cmsis(monkeypatch)
    rm = parse_svd(write(tmp_path))
    assert rm.parser_backend == 'builtin'
    assert 'ecdet[hardware]' in caplog.text
    assert rm.resolve('GPIO', 'STATUS').one_to_clear_mask

def test_missing_explicit_backend_is_error(tmp_path, monkeypatch):
    without_cmsis(monkeypatch)
    with pytest.raises(ValueError, match=r'ecdet\[hardware\]'):
        parse_svd(write(tmp_path), backend='cmsis-svd')

@pytest.mark.parametrize('change', ['cluster', 'dim', 'derivedFrom'])
def test_builtin_refuses_partial_complex_result(tmp_path, change):
    source = SIMPLE
    if change == 'cluster':
        source = source.replace('<registers>', '<registers><cluster><name>X</name><addressOffset>0x100</addressOffset></cluster>')
    elif change == 'dim':
        source = source.replace('<name>status</name>', '<dim>2</dim><dimIncrement>4</dimIncrement><name>DATA%s</name>')
    else:
        source = source.replace('</peripherals>', '<peripheral derivedFrom="gpio"><name>GPIOB</name><baseAddress>0x40001000</baseAddress></peripheral></peripherals>')
    with pytest.raises(ValueError, match=r'ecdet\[hardware\]'):
        parse_svd(write(tmp_path, source), backend='builtin')

def test_enhanced_expansion(tmp_path):
    pytest.importorskip('cmsis_svd')
    source = SIMPLE.replace('<name>status</name>', '<name>status</name>')
    source = source.replace('</registers>', '''<register><dim>2</dim><dimIncrement>4</dimIncrement><name>DATA%s</name><addressOffset>0x10</addressOffset></register>
<cluster><name>CH</name><addressOffset>0x100</addressOffset><register><name>STATUS</name><addressOffset>4</addressOffset><access>read-only</access></register></cluster></registers>''')
    source = source.replace('</peripherals>', '<peripheral derivedFrom="gpio"><name>GPIOB</name><baseAddress>0x40001000</baseAddress></peripheral></peripherals>')
    rm = parse_svd(write(tmp_path, source))
    assert {r.abs_addr for regs in rm.by_peripheral.values() for r in regs.values()} == {base+offset for base in [0x40000000,0x40001000] for offset in [0,0x10,0x14,0x104]}
    assert sum(map(len, rm.by_peripheral.values())) == 8
    assert not rm.lookup(0x40001104).writable

@pytest.mark.parametrize('content', ['<device>', '<wrong/>', SIMPLE.replace('<bitWidth>1</bitWidth>', '<bitWidth>0</bitWidth>')])
def test_invalid_svd_is_error(tmp_path, content):
    with pytest.raises(ValueError):
        parse_svd(write(tmp_path,content), backend='builtin')

@pytest.mark.parametrize('missing', [True, False])
def test_context_records_failed_svd(tmp_path, missing, caplog):
    path = tmp_path/'missing.svd' if missing else write(tmp_path,'<device>')
    hw = build_hw_context(finalize_facts([]), path)
    assert hw.regmap is None
    assert 'SVD' in caplog.text
    assert 'failed' in caplog.text.lower()

def test_original_sample_addresses():
    path = Path(__file__).parent.parent/'examples'/'svd_demo'/'STM32F407.svd'
    rm = parse_svd(path, backend='builtin')
    assert {r.abs_addr for regs in rm.by_peripheral.values() for r in regs.values()} == {0x40020000,0x40020010,0x40020018,0x40020014}
