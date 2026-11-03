"""Reject malformed SVD metadata before it can produce misleading addresses."""

import pytest

from ecdet.l3_analysis.hw_model.svd import parse_svd


SIMPLE = '''<device><name>T</name><size>32</size><peripherals>
<peripheral><name>GPIO</name><baseAddress>0x40000000</baseAddress><registers>
<register><name>STATUS</name><addressOffset>0</addressOffset><access>read-only</access></register>
</registers></peripheral></peripherals></device>'''

ARRAY = SIMPLE.replace(
    '<name>STATUS</name>',
    '<dim>2</dim><dimIncrement>4</dimIncrement><dimIndex>0,1</dimIndex><name>STATUS%s</name>',
)


@pytest.fixture(params=['builtin', 'cmsis-svd'])
def backend(request):
    if request.param == 'cmsis-svd':
        pytest.importorskip('cmsis_svd')
    return request.param


def _write(tmp_path, source):
    path = tmp_path / 'validation.svd'
    path.write_text(source, encoding='utf-8')
    return path


def test_namespace_has_same_register_map(tmp_path, backend):
    plain = parse_svd(_write(tmp_path, SIMPLE), backend=backend)
    namespaced = SIMPLE.replace('<device>', '<device xmlns="http://www.keil.com/pack/2018/01/CMSIS-SVD">')
    mapped = parse_svd(_write(tmp_path, namespaced), backend=backend)
    assert mapped.device == plain.device == 'T'
    assert sum(len(regs) for regs in mapped.by_peripheral.values()) == 1
    assert mapped.resolve('GPIO', 'STATUS') == plain.resolve('GPIO', 'STATUS')
    assert mapped.lookup(0x40000000).access == 'read-only'


INVALID = {
    'duplicate_peripheral': SIMPLE.replace(
        '</peripherals>',
        '<peripheral><name>GPIO</name><baseAddress>0x40001000</baseAddress><registers>'
        '<register><name>OTHER</name><addressOffset>0</addressOffset></register>'
        '</registers></peripheral></peripherals>',
    ),
    'unknown_access': SIMPLE.replace('read-only', 'typo-only'),
    'zero_size': SIMPLE.replace('<size>32</size>', '<size>0</size>'),
    'negative_offset': SIMPLE.replace('<addressOffset>0</addressOffset>', '<addressOffset>-4</addressOffset>'),
    'negative_stride': ARRAY.replace('<dimIncrement>4</dimIncrement>', '<dimIncrement>-4</dimIncrement>'),
    'zero_dim': ARRAY.replace('<dim>2</dim>', '<dim>0</dim>'),
    'negative_dim': ARRAY.replace('<dim>2</dim>', '<dim>-1</dim>'),
    'short_dim_index': ARRAY.replace('<dimIndex>0,1</dimIndex>', '<dimIndex>0</dimIndex>'),
    'undefined_derived': SIMPLE.replace(
        '<peripheral>', '<peripheral derivedFrom="MISSING">',
    ).replace(
        '<registers>\n<register><name>STATUS</name><addressOffset>0</addressOffset><access>read-only</access></register>\n</registers>', '',
    ),
    'cyclic_derived': '''<device><name>T</name><size>32</size><peripherals>
<peripheral derivedFrom="B"><name>A</name><baseAddress>0x40000000</baseAddress></peripheral>
<peripheral derivedFrom="A"><name>B</name><baseAddress>0x40001000</baseAddress></peripheral>
</peripherals></device>''',
}


@pytest.mark.parametrize('source', INVALID.values(), ids=INVALID.keys())
def test_invalid_metadata_is_rejected(tmp_path, backend, source):
    with pytest.raises(ValueError):
        parse_svd(_write(tmp_path, source), backend=backend)
