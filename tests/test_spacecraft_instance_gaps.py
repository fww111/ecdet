"""Independent regression pairs for the teammate's concrete missed instances."""
import pytest
from test_detector_regressions import scan


@pytest.mark.parametrize('source',[
    'void f(int x){if(x){x++;} return; x++;}',
    'void f(int x){while(x){x--;} return; x++;}',
])
def test_unconditional_return_after_block(tmp_path,source):
    assert any(a.rule_id=='MISRA C:2012 2.1' for a in scan(tmp_path,source))


@pytest.mark.parametrize('source',[
    'void f(int x){if(x) return; x++;}',
    'void f(int x){if(x){return;} x++;}',
    'void f(int x){if(x){x++;} else return; x++;}',
    'void f(int x){if(x)goto done;return;done:x++;}',
])
def test_reachable_statement_not_flagged(tmp_path,source):
    assert not any(a.rule_id=='MISRA C:2012 2.1' for a in scan(tmp_path,source))


@pytest.mark.parametrize('type_name',['float','double'])
def test_floating_local_address_pair(tmp_path,type_name):
    bad=f'{type_name} *f(void){{{type_name} value=0;return &value;}}'
    good=bad.replace(f'{{{type_name}',f'{{static {type_name}')
    assert any(a.rule_id=='MISRA C:2012 18.6' for a in scan(tmp_path,bad))
    assert not any(a.rule_id=='MISRA C:2012 18.6' for a in scan(tmp_path,good))


@pytest.mark.parametrize('bad,good',[
    ('void f(double *out){double snapshot[3];memcpy(out,snapshot,48);}',
     'void f(double *out){double snapshot[3];memcpy(out,snapshot,24);}'),
    ('struct T{char data[256];};void f(struct T *p){char staging[16];memcpy(p->data,staging,32u);}',
     'struct T{char data[256];};void f(struct T *p){char staging[16];memcpy(p->data,staging,16u);}'),
    ('#define LENGTH 16u\nvoid f(char *out){char source[8];memcpy(out,source,LENGTH);}',
     '#define LENGTH 8u\nvoid f(char *out){char source[8];memcpy(out,source,LENGTH);}'),
    ('void f(char *out,unsigned n){char source[8];if(n>16)return;memmove(out,source,n);}',
     'void f(char *out,unsigned n){char source[8];if(n>sizeof(source))return;memmove(out,source,n);}'),
    ('void f(char *out){short source[4];memcpy(out,source+3,4u);}',
     'void f(char *out){short source[4];memcpy(out,source+3,2u);}'),
    ('void f(char *out){short source[4];memcpy(out,&source[3],4u);}',
     'void f(char *out){short source[4];memcpy(out,&source[3],2u);}'),
])
def test_source_capacity_pairs(tmp_path,bad,good):
    pytest.importorskip('tree_sitter_c')
    assert any(a.rule_id=='MISRA C:2012 21.17' for a in scan(tmp_path,bad))
    assert not any(a.rule_id=='MISRA C:2012 21.17' for a in scan(tmp_path,good))


def test_array_parameter_has_unknown_caller_capacity(tmp_path):
    assert not any(a.rule_id=='MISRA C:2012 21.17' for a in scan(tmp_path,
        'void f(char *out,char source[8]){memcpy(out,source,16u);}'))


def test_source_scope_does_not_leak_between_functions(tmp_path):
    source='void a(char *out){char source[4];memcpy(out,source,4u);}\nvoid b(char *out){char source[32];memcpy(out,source,32u);}'
    assert not any(a.rule_id=='MISRA C:2012 21.17' for a in scan(tmp_path,source))


def test_source_alert_not_duplicated(tmp_path):
    source='void f(char *out){char source[4];memcpy(out,source,8);}'
    assert len([a for a in scan(tmp_path,source) if a.rule_id=='MISRA C:2012 21.17'])==1


def test_source_offset_remaining_capacity_guard(tmp_path):
    source='void f(char *out,unsigned offset,unsigned n){char source[8];if(offset>8||n>8-offset)return;memcpy(out,source+offset,n);}'
    assert not any(a.rule_id=='MISRA C:2012 21.17' for a in scan(tmp_path,source))


def test_nested_array_shadow_does_not_change_outer_capacity(tmp_path):
    source='void f(char *out){char source[32];{char source[4];memcpy(out,source,4u);}memcpy(out,source,32u);}'
    assert not any(a.rule_id=='MISRA C:2012 21.17' for a in scan(tmp_path,source))
