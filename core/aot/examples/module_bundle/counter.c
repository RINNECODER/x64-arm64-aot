#include "api.h"

unsigned shared_value = 10;
BUNDLE_TLS unsigned counter_tls = 7;
static BUNDLE_TLS unsigned zero;

void counter_init(void) { shared_value = 100; counter_tls = 7; record_event(10); }
void counter_fini(void) { record_event(110); shared_value = 0; }
unsigned counter_step(unsigned value) { counter_tls += value; return counter_tls + shared_value; }
unsigned counter_zero(void) { return zero++; }
unsigned* counter_address(void) { return &counter_tls; }
