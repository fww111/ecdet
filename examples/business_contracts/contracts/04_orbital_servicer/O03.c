#include "ecdet_contract.h"
#include "app.h"
int main(void){uint32_t stamps[]={0u,100u,UINT32_MAX-50u};uint32_t ages[]={0u,749u,750u,751u,2000u};
 for(unsigned s=0;s<3;s++)for(unsigned a=0;a<5;a++)for(unsigned valid=0;valid<2;valid++){
  Mission m={0};m.target_valid=valid;m.nav_timestamp=stamps[s];
  ECDET_CHECK(os_navigation_valid(&m,stamps[s]+ages[a])==(valid && ages[a]<=750u));
 }ECDET_PASS();}
