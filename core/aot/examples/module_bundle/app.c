#include "api.h"

void app_init(void) { record_event(30); }
void app_fini(void) { record_event(130); }

void* app_worker(void* opaque) {
    if (counter_address() != &counter_tls) return 0;
    worker_fill((BundleRequest*)opaque);
    return opaque;
}

int app_run(BundleRequest* first, BundleRequest* second) {
    BundleThread threads[2];
    void* results[2];
    if (scePthreadCreate(&threads[0], 0, app_worker, first, "first") != 0) return 1;
    if (scePthreadCreate(&threads[1], 0, app_worker, second, "second") != 0) return 2;
    if (scePthreadJoin(threads[0], &results[0]) != 0) return 3;
    if (scePthreadJoin(threads[1], &results[1]) != 0) return 4;
    return results[0] != first || results[1] != second;
}
