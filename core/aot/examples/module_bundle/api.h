#ifndef ANYPS5_MODULE_BUNDLE_API_H
#define ANYPS5_MODULE_BUNDLE_API_H

#ifdef __cplusplus
extern "C" {
#define BUNDLE_TLS thread_local
#else
#define BUNDLE_TLS _Thread_local
#endif

typedef struct BundleRequest {
    unsigned input;
    unsigned result;
    unsigned counter_zero;
    unsigned worker_zero;
    unsigned long counter_address;
    unsigned long worker_address;
    unsigned char digest[32];
} BundleRequest;

extern unsigned shared_value;
extern BUNDLE_TLS unsigned counter_tls;
extern BUNDLE_TLS unsigned worker_tls;
void counter_init(void);
void counter_fini(void);
unsigned counter_step(unsigned value);
unsigned counter_zero(void);
unsigned* counter_address(void);
void worker_init(void);
void worker_fini(void);
void worker_fill(BundleRequest* request);
unsigned* worker_address(void);
void app_init(void);
void app_fini(void);
void* app_worker(void* request);
int app_run(BundleRequest* first, BundleRequest* second);
void record_event(unsigned value);
void wait_peers(void);
typedef struct PthreadPrivate* BundleThread;
typedef struct PthreadAttrPrivate* BundleThreadAttr;
int scePthreadCreate(BundleThread* thread, const BundleThreadAttr* attributes, void* (*entry)(void*), void* argument, const char* name);
int scePthreadJoin(BundleThread thread, void** result);

#ifdef __cplusplus
}
#endif

#endif
