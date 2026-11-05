from test_detector_regressions import scan
from ecdet.l2_ir.model import Provenance


def test_systick_entry_keeps_external_linkage(tmp_path):
    alerts=scan(tmp_path,'void SysTick_Handler(void){}')
    assert not any(a.rule_id=='MISRA C:2012 8.7' for a in alerts)


def test_shared_access_is_a_candidate_not_a_proven_race(tmp_path):
    alerts=scan(tmp_path,'volatile unsigned int tick;\nvoid SysTick_Handler(void){tick++;}\nvoid task(void){unsigned int n=tick;}')
    race=next(a for a in alerts if a.rule_id=='ECDET-ISR-RACE')
    assert race.provenance==Provenance.SUSPECTED


def test_main_loop_access_is_included(tmp_path):
    alerts=scan(tmp_path,'volatile unsigned int count;\nvoid Timer_IRQHandler(void){count++;}\nint main(void){for(;;){count++;}}')
    assert any(a.rule_id=='ECDET-ISR-RACE' for a in alerts)
