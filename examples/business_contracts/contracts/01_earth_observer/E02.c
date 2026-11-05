#include "ecdet_contract.h"
#include "app.h"
int main(void){
 uint32_t stamps[]={0u,100u,UINT32_MAX-50u}; uint32_t ages[]={0u,499u,500u,501u,1900u};
 for(unsigned s=0;s<3;s++)for(unsigned a=0;a<5;a++)for(unsigned valid=0;valid<2;valid++){
  Mission m={0};m.star_valid=valid;m.star_timestamp=stamps[s];m.star_angle[0]=10.0f;
  eo_fuse_star(&m,stamps[s]+ages[a]);
  ECDET_CHECK((m.angle[0]!=0.0f)==(valid && ages[a]<=500u));
 } ECDET_PASS();
}
