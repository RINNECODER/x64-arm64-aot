#ifndef APS5_HLE_LOG_H
#define APS5_HLE_LOG_H

// Fork-only HLE-boundary call log shared by the Rosetta stub runtime and the
// native NID-binding layer. ANYPS5_HLE_LOG=<file> enables it. The file is a
// 2-word header followed by variable-length records:
//
//   u64 sequence, u64 thread, u32 name_length, u32 flags (0 call, 1 return),
//   u64 args[6], u64 result, u8 name[name_length] padded to 8 bytes
//
// A call record carries the name and args; a return record carries name_length 0
// and the result, and shares the call's sequence. The format is fixed and
// engine-independent so tools/native/hle_diff.py can align two logs.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APS5_HLE_LOG_MAGIC 0x474F4C48u  /* 'HLOG' */
#define APS5_HLE_LOG_VERSION 1u
#define APS5_HLE_LOG_ARGS 6
#define APS5_HLE_LOG_CALL 0u
#define APS5_HLE_LOG_RETURN 1u

int HleLogEnabled(void);
uint64_t HleLogCall(const char* name, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5);
void HleLogReturn(uint64_t sequence, uint64_t result);

#ifdef __cplusplus
}
#endif

#endif
