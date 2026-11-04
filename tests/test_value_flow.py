"""Boundary and lifetime checks must distinguish faulty and guarded code."""
import pytest
from test_detector_regressions import scan

pytest.importorskip('tree_sitter_c')

HEADER='typedef struct {unsigned char bytes[24]; int axes[3]; unsigned fuel; char *retry;} State;'


def test_explicit_narrowing_is_not_a_sign_reinterpretation_alert(tmp_path):
    source='unsigned char encode(int value){return (unsigned char)value;}'
    assert not any(a.rule_id=='ECDET-CWE-195' for a in scan(tmp_path,source))


@pytest.mark.parametrize('bad,good,rule', [
 ('void f(State *s,const char *p,unsigned n){if(n>40)return;memcpy(s->bytes,p,n);}',
  'void f(State *s,const char *p,unsigned n){if(n>sizeof(s->bytes))return;memcpy(s->bytes,p,n);}', 'CERT C STR31-C'),
 ('void f(State *s,unsigned n){if(n>3)return;s->axes[n]=1;}',
  'void f(State *s,unsigned n){if(n>=3)return;s->axes[n]=1;}', 'CERT C ARR30-C'),
 ('void f(State *s,int n){if(n>=3)return;s->axes[n]=1;}',
  'void f(State *s,int n){if(n<0||n>=3)return;s->axes[n]=1;}', 'CERT C ARR30-C'),
 ('void f(State *s,unsigned n){if(n>3)return;for(unsigned i=0;i<=n;i++)s->axes[i]=0;}',
  'void f(State *s,unsigned n){if(n>3)return;for(unsigned i=0;i<n;i++)s->axes[i]=0;}', 'CERT C ARR30-C'),
 ('void f(State *s,const int *p,unsigned n){if(n>5)return;memcpy(s->axes,p,n*sizeof(*p));}',
  'void f(State *s,const int *p,unsigned n){if(n>3)return;memcpy(s->axes,p,n*sizeof(*p));}', 'CERT C STR31-C'),
 ('void f(char *in){char out[24];int n=snprintf(out,sizeof(out),"%s",in);if(n<0)return;send(out,n);}',
  'void f(char *in){char out[24];int n=snprintf(out,sizeof(out),"%s",in);if(n<0||n>=sizeof(out))return;send(out,n);}', 'CERT C ARR30-C'),
 ('void f(State *s,unsigned amount){s->fuel-=amount;}',
  'void f(State *s,unsigned amount){if(amount>s->fuel)return;s->fuel-=amount;}', 'CERT C INT30-C'),
 ('int f(unsigned now,unsigned last,unsigned wait){return now>last+wait;}',
  'int f(unsigned now,unsigned last,unsigned wait){return (unsigned)(now-last)>wait;}', 'CERT C INT30-C'),
 ('unsigned f(short raw){return (unsigned short)raw;}',
  'unsigned f(short raw){if(raw<0)return 0;return (unsigned short)raw;}', 'ECDET-CWE-195'),
 ('void done(State *s){free(s->retry);} void retry(State *s){if(s->retry)send(s->retry,10);}',
  'void done(State *s){free(s->retry);s->retry=0;} void retry(State *s){if(s->retry)send(s->retry,10);}', 'ECDET-CWE-416'),
 ('void f(State *s,char *p,unsigned short a,unsigned short b){unsigned short end=(unsigned short)(a+b);if(end>24)return;memcpy(s->bytes+a,p,b);}',
  'void f(State *s,char *p,unsigned short a,unsigned short b){unsigned end=(unsigned)a+b;if(end>24)return;memcpy(s->bytes+a,p,b);}', 'CERT C STR31-C'),
])
def test_guarded_pairs(tmp_path,bad,good,rule):
    assert any(a.rule_id==rule for a in scan(tmp_path,HEADER+bad))
    assert not any(a.rule_id==rule for a in scan(tmp_path,HEADER+good))


def test_unrelated_or_conditional_guard_does_not_protect(tmp_path):
    source=HEADER+'void f(State *s,char *p,unsigned n,int flag){if(flag){if(n>24)return;}memcpy(s->bytes,p,n);}'
    assert any(a.rule_id=='CERT C STR31-C' for a in scan(tmp_path,source))


def test_short_circuit_cast_guard(tmp_path):
    source='void f(char *p){char b[24];int n=snprintf(b,sizeof(b),"%s",p);if(n<0||(unsigned)n>=sizeof(b))return;send(b,n);}'
    assert not [a for a in scan(tmp_path,source) if a.engine=='builtin-flow']


def test_capacity_minus_offset_guard(tmp_path):
    source=HEADER+'void f(State *s,unsigned offset,unsigned n){if(offset>24||n>24-offset)return;for(unsigned i=0;i<n;i++)s->bytes[offset+i]=0;}'
    assert not [a for a in scan(tmp_path,source) if a.engine=='builtin-flow']


def test_switch_branch_guard(tmp_path):
    source=HEADER+'void f(State *s,char *p,unsigned n,int op){switch(op){case 1: if(n<=24){memcpy(s->bytes,p,n);}break;default:break;}}'
    assert not [a for a in scan(tmp_path,source) if a.engine=='builtin-flow']


def test_conditional_reset_does_not_hide_dangling_field(tmp_path):
    source=HEADER+'void done(State *s,int flag){free(s->retry);if(flag)s->retry=0;}'
    assert any(a.rule_id=='ECDET-CWE-416' for a in scan(tmp_path,source))


def test_partition_length_guard(tmp_path):
    bad='void patch(unsigned region,unsigned offset,char *data,unsigned n){if(region>=8||offset>=64)return;write_block(region*64+offset,data,n);}'
    good=bad.replace('offset>=64','offset>=64||n>64-offset')
    assert any(a.rule_id=='ECDET-CWE-119' for a in scan(tmp_path,bad))
    assert not any(a.rule_id=='ECDET-CWE-119' for a in scan(tmp_path,good))
