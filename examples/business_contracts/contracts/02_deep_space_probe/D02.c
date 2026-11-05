#include "ecdet_contract.h"
#include "app.h"
int main(void){for(int mode=DS_CRUISE;mode<=DS_SAFE;mode++){
 Mission m={0};m.mode=(DsMode)mode;bool result=ds_instrument_enable(&m);
 ECDET_CHECK(result==(mode!=DS_SAFE)); ECDET_CHECK(m.instrument_on==(mode!=DS_SAFE));
} ECDET_PASS();}
