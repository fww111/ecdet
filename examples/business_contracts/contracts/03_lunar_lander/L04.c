#include "ecdet_contract.h"
#include "app.h"
int main(void){for(int left=0;left<2;left++)for(int right=0;right<2;right++){
 Mission m={0};m.mode=LD_DESCENT;m.engine_enabled=true;m.thrust=1.0f;m.contact_left=left;m.contact_right=right;
 bool result=ld_touchdown(&m); ECDET_CHECK(result==(left && right));
 ECDET_CHECK(m.engine_enabled==!(left && right)); ECDET_CHECK((m.mode==LD_LANDED)==(left && right));
 ECDET_CHECK(m.thrust==((left && right)?0.0f:1.0f));
} ECDET_PASS();}
