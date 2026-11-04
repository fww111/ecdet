"""Root-cause regressions from the spacecraft audit, with independent controls."""
import pytest

from ecdet.l3_analysis.engine import AnalysisTarget, BuiltinEngine
from ecdet.l2_ir.model import Provenance


def scan(tmp_path, source, headers=None):
    files = {"unit.c": source, **(headers or {})}
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    engine = BuiltinEngine()
    return engine.run(AnalysisTarget(tmp_path, list(map(type(tmp_path), files))),
                      {r.rule_id for r in engine.rules()})


@pytest.mark.parametrize("source,rule", [
    ('void f(void){char b[20]; sprintf(b,"%d",1); snprintf(b,sizeof(b),"%s","x");}', 'CERT C FIO30-C'),
    ('static const char *prompt="ready"; void f(void){printf(prompt);}', 'CERT C FIO30-C'),
    ('static int helper(void){return 0;} static void f(void){helper();}', 'MISRA C:2012 8.7'),
    ('typedef struct {int count;} A; static void f(A *p){p->count=0;}', 'MISRA C:2012 8.7'),
    ('typedef struct {int count;} A; void f(A *p){p->count=0;}', 'MISRA C:2012 8.9'),
    ('void f(int x){switch(x){case 1: if(x){x++;} break; default: return;}}', 'MISRA C:2012 16.3'),
    ('void f(int x){switch(x){case 1: {if(x){x++;} break;} default: return;}}', 'MISRA C:2012 16.3'),
    ('void f(int x){switch(x){case 1: again: x++; break; default: return;}}', 'MISRA C:2012 16.3'),
    ('void f(int axis){static const float scale[3]={1,2,3};float x; x=2 * scale[axis];}', 'MISRA C:2012 18.8'),
    ('void f(unsigned char *data){unsigned short x=(unsigned short)data[0];}', 'MISRA C:2012 11.4'),
    ('typedef struct {unsigned int value;} A; void f(A *p){unsigned long x=(unsigned long)p->value;}', 'MISRA C:2012 11.4'),
    ('void a(char *value){} void b(unsigned value){unsigned short x=(unsigned short)value;}', 'MISRA C:2012 11.4'),
    ('void f(void){char buf[12]; const unsigned char *p=(const unsigned char *)buf;}', 'MISRA C:2012 11.4'),
    ('void f(void){char buf[12]; const unsigned char *p=(const unsigned char *)buf;}', 'MISRA C:2012 11.3'),
    ('void f(void){int a[3];int i;for(i=0;i<3;i++){a[i]=0;} i=3;}', 'CERT C ARR30-C'),
    ('void f(void){int a[3];int i=1;a[i]=0;i=5;}', 'CERT C ARR30-C'),
    ('#include <math.h>\nvoid f(float x){if(x && isfinite(x) && fabsf(x)>1){}}', 'MISRA C:2012 13.5'),
    ('#include <stdio.h>\n#include <math.h>\nvoid f(void *s){if(!feof(s)){float x=fabsf(1);}}', 'MISRA C:2012 17.3'),
    ('typedef struct {void (*run)(void);} T; void f(T *p){p->run();}', 'MISRA C:2012 17.3'),
])
def test_known_clean_operations(tmp_path, source, rule):
    assert not [a for a in scan(tmp_path, source) if a.rule_id == rule]


def test_header_macro_references(tmp_path):
    alerts = scan(tmp_path, '#include "api.h"\nint f(void){return CAPACITY+COUNT(3);}',
                  {'api.h':'#define CAPACITY 8\n#define COUNT(x) (x)\n'})
    assert not [a for a in alerts if a.rule_id in {'MISRA C:2012 2.5','MISRA C:2012 17.3'}]


def test_conditional_out_of_bounds_is_not_a_proof(tmp_path):
    alerts=scan(tmp_path,'void f(int flag){int a[3];int i=1;if(flag){i=5;}a[i]=0;}')
    assert not any(a.rule_id=='CERT C ARR30-C' and a.provenance==Provenance.PROVEN for a in alerts)


@pytest.mark.parametrize("source,rule", [
    ('void f(char *input){printf(input);}', 'CERT C FIO30-C'),
    ('void f(char *p){unsigned long x=(unsigned long)p;}', 'MISRA C:2012 11.4'),
    ('void f(int x){switch(x){case 1: if(x){break;} default: x++;}}', 'MISRA C:2012 16.3'),
    ('void f(int n){int a[n];}', 'MISRA C:2012 18.8'),
    ('void f(void){int a[3];int i=5;a[i]=0;}', 'CERT C ARR30-C'),
    ('void f(void){missing_api();}', 'MISRA C:2012 17.3'),
    ('int mutate(void); void f(int x){if(x && mutate()){}}', 'MISRA C:2012 13.5'),
])
def test_true_findings_remain(tmp_path, source, rule):
    assert any(a.rule_id == rule for a in scan(tmp_path, source))


def test_open_critical_region_is_not_outside(tmp_path):
    alerts=scan(tmp_path, 'volatile unsigned int ticks;\nvoid TIMER_IRQHandler(void){ticks++;}\n'
                'void worker(void){taskENTER_CRITICAL();ticks++;}')
    ids={a.rule_id for a in alerts}
    assert 'ECDET-HW-CRITICAL-PAIR' in ids
    assert 'ECDET-HW-VOLATILE-RMW' not in ids
    assert 'ECDET-ISR-RACE' not in ids


def test_optional_critical_enter_does_not_protect_later_access(tmp_path):
    alerts=scan(tmp_path,'volatile unsigned int ticks;\nvoid TIMER_IRQHandler(void){ticks++;}\n'
                'void worker(int ready){if(ready){taskENTER_CRITICAL();}ticks++;}')
    assert any(a.rule_id=='ECDET-HW-VOLATILE-RMW' for a in alerts)


@pytest.mark.parametrize('helper', [
    'volatile unsigned int ready; int helper(void){return ready;}',
    'int helper(void){static int calls;return ++calls;}',
    'int value; int helper(void){int *p=&value;*p=1;return 1;}',
    'struct Ops {int (*run)(void);}; struct Ops ops; int helper(void){return ops.run();}',
])
def test_observable_helper_effects_are_not_suppressed(tmp_path,helper):
    alerts=scan(tmp_path,helper+' void f(int x){if(x && helper())return;}')
    assert any(a.rule_id=='MISRA C:2012 13.5' for a in alerts)
