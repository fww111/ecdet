#include "ecdet_contract.h"
#include "eps.h"
eps_state_t g_eps;
int main(void){uint32_t duties[]={0u,799u,800u,801u,900u,UINT32_MAX};
 for(uint32_t ch=0;ch<EPS_HEATER_COUNT;ch++)for(unsigned d=0;d<6;d++){
  g_eps.heater_duty[ch]=123u;heater_set_duty(ch,duties[d]);
  ECDET_CHECK(g_eps.heater_duty[ch]<=800u);
  if(duties[d]<=800u){ECDET_CHECK(g_eps.heater_duty[ch]==duties[d]);}
 }
 uint32_t saved=g_eps.heater_duty[0];heater_set_duty(EPS_HEATER_COUNT,500u);ECDET_CHECK(g_eps.heater_duty[0]==saved);
 ECDET_PASS();}
