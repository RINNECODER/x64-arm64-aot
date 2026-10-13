#include "api.h"
#include "self_update_sha256.c"

BUNDLE_TLS unsigned worker_tls = 20;
static BUNDLE_TLS unsigned zero;

void worker_init(void) { worker_tls = 20; record_event(20); }
void worker_fini(void) { record_event(120); worker_tls = 0; }
unsigned* worker_address(void) { return &worker_tls; }

void worker_fill(BundleRequest* request) {
    unsigned value = request->input;
    unsigned char message[4] = {(unsigned char)value, (unsigned char)(value >> 8), (unsigned char)(value >> 16), (unsigned char)(value >> 24)};
    self_update_sha256 hash;
    request->counter_address = (unsigned long)counter_address();
    request->worker_address = (unsigned long)worker_address();
    request->counter_zero = counter_zero();
    request->worker_zero = zero++;
    request->result = counter_step(value) + worker_tls++ + shared_value;
    self_update_sha256_start(&hash);
    self_update_sha256_add(&hash, message, 1);
    self_update_sha256_add(&hash, message + 1, 3);
    self_update_sha256_finish(&hash, request->digest);
    wait_peers();
}
