#include "ecdet_contract.h"
#include "app.h"
#include <math.h>
int main(void){float speeds[]={-0.1f,-0.021f,-0.02f,0.0f,0.02f,0.021f,0.1f};float ranges[]={0.0f,0.5f,0.501f};
 for(int mode=OS_HOLD;mode<=OS_SAFE;mode++)for(unsigned s=0;s<7;s++)for(unsigned r=0;r<3;r++)for(unsigned permit=0;permit<2;permit++){
  Mission m={0};m.mode=(OsMode)mode;m.range=ranges[r];m.closing_speed=speeds[s];m.permit=permit;
  bool expected=permit && mode==OS_CAPTURE && ranges[r]<=0.5f && fabsf(speeds[s])<=0.02f;
  bool result=os_capture(&m);ECDET_CHECK(result==expected);ECDET_CHECK(m.latch_closed==expected);
  ECDET_CHECK(m.captures==(expected?1u:0u));ECDET_CHECK(m.mode==(expected?OS_SERVICE:(OsMode)mode));
 }ECDET_PASS();}
