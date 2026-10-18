#!/usr/bin/env python3
"""x86 call recording for the differential harness.

Runs the guest function under test on the x86 side with every direct `call` (and direct tail
`jmp`) redirected through a pair of trampolines. The entry trampoline snapshots the argument
state and the guest scratch/stack, sets up a return trampoline in place of the return address and
jumps to the real callee; the return trampoline snapshots the callee's return state and memory
and returns to the instruction after the call. The records are dumped to a file.

The ARM64 side then compiles the function alone, with each recorded callee declared `external`,
and links generated replay stubs that write the recorded return register file and memory diff into
the uniform register file. That is what lets a function that calls others be verified without its
callees having to compile.

usage: import this module (difftest.difftest_full drives it)
"""
import ctypes
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

BASE = 0x140000000
SCRATCH = BASE + 0x60000000
SCRATCH_SIZE = 0x10000
ISLAND = BASE + 0x40000000
STACK_SNAP = BASE + 0x700F0000
STACK_SNAP_SIZE = 0x4000
SNAP_SIZE = SCRATCH_SIZE + STACK_SNAP_SIZE
MAX_RECORDS = 512
FRAME_OFFSETS = {  # struct saved_frame
    'xmm': 8, 'ymm': 264, 'r15': 520, 'r14': 528, 'r13': 536, 'r12': 544, 'rbp': 552,
    'rbx': 560, 'r11': 568, 'r10': 576, 'r9': 584, 'r8': 592, 'rdi': 600, 'rsi': 608,
    'rdx': 616, 'rcx': 624, 'rax': 632, 'flags': 640, 'retaddr': 648, 'stackargs': 656,
}

# The harness register order (abi.UNIFORM_GPRS): rax rcx rdx rbx rsp rbp rsi rdi r8..r15.
GPR_ORDER = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'] + [f'r{i}' for i in range(8, 16)]

RECORDER_C = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#define BASE 0x140000000ULL
#define ISLAND_OFFSET 0x40000000ULL
#define SCRATCH (BASE + 0x60000000ULL)
#define SCRATCH_SIZE 0x10000ULL
#define STACK_SNAP (BASE + 0x700F0000ULL)
#define STACK_SNAP_SIZE 0x4000ULL
#define SNAP_SIZE (SCRATCH_SIZE + STACK_SNAP_SIZE)
#define MAX_RECORDS 512
struct regs { uint64_t r[16]; };
extern uint64_t invoke(void* entry, struct regs* in, struct regs* out, uint64_t* stack, uint64_t stack_words);
uint64_t g_frame, g_out, g_entry, g_r9, g_r10, g_r11, g_zero;
__asm__(
".text\n.globl _invoke\n_invoke:\n"
"  pushq %rbp\n  movq %rsp, %rbp\n"
"  movq %rbp, _g_frame(%rip)\n  movq %rdx, _g_out(%rip)\n  movq %rdi, _g_entry(%rip)\n"
"  pushq %rbx\n  pushq %r12\n  pushq %r13\n  pushq %r14\n  pushq %r15\n  subq $32, %rsp\n"
"  movq %rsi, %r10\n  leaq -8(%rcx,%r8,8), %rsp\n"
"  movq 0(%r10), %rax\n  movq 8(%r10), %rbx\n  movq 16(%r10), %rcx\n  movq 24(%r10), %rdx\n"
"  movq 32(%r10), %rsi\n  movq 40(%r10), %rdi\n  movq 48(%r10), %rbp\n  movq 64(%r10), %r8\n  movq 72(%r10), %r9\n"
"  movq 88(%r10), %r11\n  movq 96(%r10), %r12\n  movq 104(%r10), %r13\n  movq 112(%r10), %r14\n  movq 120(%r10), %r15\n"
"  movq 80(%r10), %r10\n  pushq _g_zero(%rip)\n  popfq\n  callq *_g_entry(%rip)\n"
"  movq %r9, _g_r9(%rip)\n  movq %r10, _g_r10(%rip)\n  movq %r11, _g_r11(%rip)\n  movq _g_out(%rip), %r9\n"
"  movq %rax, 0(%r9)\n  movq %rbx, 8(%r9)\n  movq %rcx, 16(%r9)\n  movq %rdx, 24(%r9)\n"
"  movq %rsi, 32(%r9)\n  movq %rdi, 40(%r9)\n  movq %rbp, 48(%r9)\n  movq %r8, 64(%r9)\n"
"  movq _g_r9(%rip), %r10\n  movq %r10, 72(%r9)\n  movq _g_r10(%rip), %r10\n  movq %r10, 80(%r9)\n"
"  movq _g_r11(%rip), %r10\n  movq %r10, 88(%r9)\n"
"  movq %r12, 96(%r9)\n  movq %r13, 104(%r9)\n  movq %r14, 112(%r9)\n  movq %r15, 120(%r9)\n"
"  movq _g_frame(%rip), %rbp\n  leaq -40(%rbp), %rsp\n  popq %r15\n  popq %r14\n  popq %r13\n  popq %r12\n  popq %rbx\n  popq %rbp\n  ret\n");

struct saved_frame {
    uint64_t pad;
    unsigned char xmm[256];
    unsigned char ymm[256];
    uint64_t r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rdi, rsi, rdx, rcx, rax;
    uint64_t flags;
    uint64_t retaddr;
    uint64_t stackargs[0];
};

struct record {
    uint64_t site, target, tail, seq, arg_rsp;
    uint64_t arg_gprs[16];
    unsigned char arg_xmm[256];
    uint64_t ret_gprs[16];
    unsigned char ret_xmm[256];
    unsigned char ret_ymm[256];
    uint64_t ret_flags;
    unsigned char* pre;
    unsigned char* post;
    int completed;
};

static void fault_handler(int sig, siginfo_t* info, void* context) {
    ucontext_t* uc = (ucontext_t*)context;
    fprintf(stderr, "[rec] fault sig=%d addr=%p rip=%llx\n", sig, info ? info->si_addr : 0, uc?(unsigned long long)uc->uc_mcontext->__ss.__rip:0);
    _exit(9);
}
static struct record g_records[MAX_RECORDS];
static int g_record_count;
static int g_pending[4096];
static int g_depth;
static uint64_t g_seq;
uint64_t aps5_target;
static uint64_t g_site_retaddr[4096];
static uint64_t g_site_target[4096];
static uint64_t g_site_tail[4096];
static int g_site_count;

static unsigned char* snapshot(void) {
    unsigned char* p = (unsigned char*)malloc(SNAP_SIZE);
    if (!p) return NULL;
    memcpy(p, (void*)SCRATCH, SCRATCH_SIZE);
    memcpy(p + SCRATCH_SIZE, (void*)STACK_SNAP, STACK_SNAP_SIZE);
    return p;
}

static void gprs_from_frame(struct saved_frame* f, uint64_t* out) {
    out[0] = f->rax; out[1] = f->rcx; out[2] = f->rdx; out[3] = f->rbx;
    out[4] = (uint64_t)f->stackargs; out[5] = f->rbp; out[6] = f->rsi; out[7] = f->rdi;
    out[8] = f->r8; out[9] = f->r9; out[10] = f->r10; out[11] = f->r11;
    out[12] = f->r12; out[13] = f->r13; out[14] = f->r14; out[15] = f->r15;
}

void aps5_record_entry(struct saved_frame* f, uint64_t retaddr, uint64_t* stackargs, uint64_t* target_out) {
    *target_out = 0;
    int found = -1;
    for (int index = 0; index < g_site_count; ++index) {
        if (g_site_retaddr[index] == retaddr) { found = index; break; }
    }
    if (found < 0 || g_record_count >= MAX_RECORDS) return;
    struct record* r = &g_records[g_record_count];
    memset(r, 0, sizeof(*r));
    r->site = retaddr - 5;
    r->target = g_site_target[found];
    r->tail = g_site_tail[found];
    r->seq = g_seq++;
    r->arg_rsp = (uint64_t)stackargs;
    gprs_from_frame(f, r->arg_gprs);
    r->arg_gprs[4] = (uint64_t)stackargs;
    memcpy(r->arg_xmm, f->xmm, 256);
    r->pre = snapshot();
    g_pending[g_depth++] = g_record_count;
    g_record_count++;
    *target_out = g_site_target[found];
}

uint64_t aps5_record_return(struct saved_frame* f) {
    if (g_depth <= 0) return 0;
    struct record* r = &g_records[g_pending[--g_depth]];
    gprs_from_frame(f, r->ret_gprs);
    r->ret_gprs[4] = (uint64_t)f->stackargs;
    memcpy(r->ret_xmm, f->xmm, 256);
    memcpy(r->ret_ymm, f->ymm, 256);
    r->ret_flags = f->flags;
    r->post = snapshot();
    r->completed = 1;
    return r->site + 5;
}

__attribute__((naked)) void aps5_entry(void) {
    __asm__ volatile(
        "pushfq\n\t"
        "pushq %rax\n\t pushq %rcx\n\t pushq %rdx\n\t pushq %rsi\n\t pushq %rdi\n\t"
        "pushq %r8\n\t pushq %r9\n\t pushq %r10\n\t pushq %r11\n\t"
        "pushq %rbx\n\t pushq %rbp\n\t pushq %r12\n\t pushq %r13\n\t pushq %r14\n\t pushq %r15\n\t"
        "subq $520, %rsp\n\t"
        "movups %xmm0, 8(%rsp)\n\t movups %xmm1, 24(%rsp)\n\t movups %xmm2, 40(%rsp)\n\t movups %xmm3, 56(%rsp)\n\t"
        "movups %xmm4, 72(%rsp)\n\t movups %xmm5, 88(%rsp)\n\t movups %xmm6, 104(%rsp)\n\t movups %xmm7, 120(%rsp)\n\t"
        "movups %xmm8, 136(%rsp)\n\t movups %xmm9, 152(%rsp)\n\t movups %xmm10, 168(%rsp)\n\t movups %xmm11, 184(%rsp)\n\t"
        "movups %xmm12, 200(%rsp)\n\t movups %xmm13, 216(%rsp)\n\t movups %xmm14, 232(%rsp)\n\t movups %xmm15, 248(%rsp)\n\t"
        "vextractf128 $1, %ymm0, 264(%rsp)\n\t vextractf128 $1, %ymm1, 280(%rsp)\n\t"
        "vextractf128 $1, %ymm2, 296(%rsp)\n\t vextractf128 $1, %ymm3, 312(%rsp)\n\t"
        "vextractf128 $1, %ymm4, 328(%rsp)\n\t vextractf128 $1, %ymm5, 344(%rsp)\n\t"
        "vextractf128 $1, %ymm6, 360(%rsp)\n\t vextractf128 $1, %ymm7, 376(%rsp)\n\t"
        "vextractf128 $1, %ymm8, 392(%rsp)\n\t vextractf128 $1, %ymm9, 408(%rsp)\n\t"
        "vextractf128 $1, %ymm10, 424(%rsp)\n\t vextractf128 $1, %ymm11, 440(%rsp)\n\t"
        "vextractf128 $1, %ymm12, 456(%rsp)\n\t vextractf128 $1, %ymm13, 472(%rsp)\n\t"
        "vextractf128 $1, %ymm14, 488(%rsp)\n\t vextractf128 $1, %ymm15, 504(%rsp)\n\t"
        "movq %rsp, %rdi\n\t"
        "movq 648(%rsp), %rsi\n\t"
        "leaq 656(%rsp), %rdx\n\t"
        "leaq _aps5_target(%rip), %rcx\n\t"
        "callq _aps5_record_entry\n\t"
        "movups 8(%rsp), %xmm0\n\t movups 24(%rsp), %xmm1\n\t movups 40(%rsp), %xmm2\n\t movups 56(%rsp), %xmm3\n\t"
        "movups 72(%rsp), %xmm4\n\t movups 88(%rsp), %xmm5\n\t movups 104(%rsp), %xmm6\n\t movups 120(%rsp), %xmm7\n\t"
        "movups 136(%rsp), %xmm8\n\t movups 152(%rsp), %xmm9\n\t movups 168(%rsp), %xmm10\n\t movups 184(%rsp), %xmm11\n\t"
        "movups 200(%rsp), %xmm12\n\t movups 216(%rsp), %xmm13\n\t movups 232(%rsp), %xmm14\n\t movups 248(%rsp), %xmm15\n\t"
        "vinsertf128 $1, 264(%rsp), %ymm0, %ymm0\n\t vinsertf128 $1, 280(%rsp), %ymm1, %ymm1\n\t"
        "vinsertf128 $1, 296(%rsp), %ymm2, %ymm2\n\t vinsertf128 $1, 312(%rsp), %ymm3, %ymm3\n\t"
        "vinsertf128 $1, 328(%rsp), %ymm4, %ymm4\n\t vinsertf128 $1, 344(%rsp), %ymm5, %ymm5\n\t"
        "vinsertf128 $1, 360(%rsp), %ymm6, %ymm6\n\t vinsertf128 $1, 376(%rsp), %ymm7, %ymm7\n\t"
        "vinsertf128 $1, 392(%rsp), %ymm8, %ymm8\n\t vinsertf128 $1, 408(%rsp), %ymm9, %ymm9\n\t"
        "vinsertf128 $1, 424(%rsp), %ymm10, %ymm10\n\t vinsertf128 $1, 440(%rsp), %ymm11, %ymm11\n\t"
        "vinsertf128 $1, 456(%rsp), %ymm12, %ymm12\n\t vinsertf128 $1, 472(%rsp), %ymm13, %ymm13\n\t"
        "vinsertf128 $1, 488(%rsp), %ymm14, %ymm14\n\t vinsertf128 $1, 504(%rsp), %ymm15, %ymm15\n\t"
        "addq $520, %rsp\n\t"
        "popq %r15\n\t popq %r14\n\t popq %r13\n\t popq %r12\n\t popq %rbp\n\t popq %rbx\n\t"
        "leaq _aps5_return(%rip), %r11\n\t"
        "movq %r11, 80(%rsp)\n\t"
        "popq %r11\n\t popq %r10\n\t popq %r9\n\t popq %r8\n\t popq %rdi\n\t popq %rsi\n\t popq %rdx\n\t popq %rcx\n\t popq %rax\n\t"
        "popfq\n\t"
        "jmpq *_aps5_target(%rip)\n\t");
}

__attribute__((naked)) void aps5_entry_tail(void) {
    __asm__ volatile(
        "pushfq\n\t"
        "pushq %rax\n\t pushq %rcx\n\t pushq %rdx\n\t pushq %rsi\n\t pushq %rdi\n\t"
        "pushq %r8\n\t pushq %r9\n\t pushq %r10\n\t pushq %r11\n\t"
        "pushq %rbx\n\t pushq %rbp\n\t pushq %r12\n\t pushq %r13\n\t pushq %r14\n\t pushq %r15\n\t"
        "subq $520, %rsp\n\t"
        "movups %xmm0, 8(%rsp)\n\t movups %xmm1, 24(%rsp)\n\t movups %xmm2, 40(%rsp)\n\t movups %xmm3, 56(%rsp)\n\t"
        "movups %xmm4, 72(%rsp)\n\t movups %xmm5, 88(%rsp)\n\t movups %xmm6, 104(%rsp)\n\t movups %xmm7, 120(%rsp)\n\t"
        "movups %xmm8, 136(%rsp)\n\t movups %xmm9, 152(%rsp)\n\t movups %xmm10, 168(%rsp)\n\t movups %xmm11, 184(%rsp)\n\t"
        "movups %xmm12, 200(%rsp)\n\t movups %xmm13, 216(%rsp)\n\t movups %xmm14, 232(%rsp)\n\t movups %xmm15, 248(%rsp)\n\t"
        "vextractf128 $1, %ymm0, 264(%rsp)\n\t vextractf128 $1, %ymm1, 280(%rsp)\n\t"
        "vextractf128 $1, %ymm2, 296(%rsp)\n\t vextractf128 $1, %ymm3, 312(%rsp)\n\t"
        "vextractf128 $1, %ymm4, 328(%rsp)\n\t vextractf128 $1, %ymm5, 344(%rsp)\n\t"
        "vextractf128 $1, %ymm6, 360(%rsp)\n\t vextractf128 $1, %ymm7, 376(%rsp)\n\t"
        "vextractf128 $1, %ymm8, 392(%rsp)\n\t vextractf128 $1, %ymm9, 408(%rsp)\n\t"
        "vextractf128 $1, %ymm10, 424(%rsp)\n\t vextractf128 $1, %ymm11, 440(%rsp)\n\t"
        "vextractf128 $1, %ymm12, 456(%rsp)\n\t vextractf128 $1, %ymm13, 472(%rsp)\n\t"
        "vextractf128 $1, %ymm14, 488(%rsp)\n\t vextractf128 $1, %ymm15, 504(%rsp)\n\t"
        "movq %rsp, %rdi\n\t"
        "movq 648(%rsp), %rsi\n\t"
        "leaq 656(%rsp), %rdx\n\t"
        "leaq _aps5_target(%rip), %rcx\n\t"
        "callq _aps5_record_entry\n\t"
        "movups 8(%rsp), %xmm0\n\t movups 24(%rsp), %xmm1\n\t movups 40(%rsp), %xmm2\n\t movups 56(%rsp), %xmm3\n\t"
        "movups 72(%rsp), %xmm4\n\t movups 88(%rsp), %xmm5\n\t movups 104(%rsp), %xmm6\n\t movups 120(%rsp), %xmm7\n\t"
        "movups 136(%rsp), %xmm8\n\t movups 152(%rsp), %xmm9\n\t movups 168(%rsp), %xmm10\n\t movups 184(%rsp), %xmm11\n\t"
        "movups 200(%rsp), %xmm12\n\t movups 216(%rsp), %xmm13\n\t movups 232(%rsp), %xmm14\n\t movups 248(%rsp), %xmm15\n\t"
        "vinsertf128 $1, 264(%rsp), %ymm0, %ymm0\n\t vinsertf128 $1, 280(%rsp), %ymm1, %ymm1\n\t"
        "vinsertf128 $1, 296(%rsp), %ymm2, %ymm2\n\t vinsertf128 $1, 312(%rsp), %ymm3, %ymm3\n\t"
        "vinsertf128 $1, 328(%rsp), %ymm4, %ymm4\n\t vinsertf128 $1, 344(%rsp), %ymm5, %ymm5\n\t"
        "vinsertf128 $1, 360(%rsp), %ymm6, %ymm6\n\t vinsertf128 $1, 376(%rsp), %ymm7, %ymm7\n\t"
        "vinsertf128 $1, 392(%rsp), %ymm8, %ymm8\n\t vinsertf128 $1, 408(%rsp), %ymm9, %ymm9\n\t"
        "vinsertf128 $1, 424(%rsp), %ymm10, %ymm10\n\t vinsertf128 $1, 440(%rsp), %ymm11, %ymm11\n\t"
        "vinsertf128 $1, 456(%rsp), %ymm12, %ymm12\n\t vinsertf128 $1, 472(%rsp), %ymm13, %ymm13\n\t"
        "vinsertf128 $1, 488(%rsp), %ymm14, %ymm14\n\t vinsertf128 $1, 504(%rsp), %ymm15, %ymm15\n\t"
        "addq $520, %rsp\n\t"
        "popq %r15\n\t popq %r14\n\t popq %r13\n\t popq %r12\n\t popq %rbp\n\t popq %rbx\n\t"
        "popq %r11\n\t popq %r10\n\t popq %r9\n\t popq %r8\n\t popq %rdi\n\t popq %rsi\n\t popq %rdx\n\t popq %rcx\n\t popq %rax\n\t"
        "popfq\n\t"
        "addq $8, %rsp\n\t"
        "jmpq *_aps5_target(%rip)\n\t");
}

__attribute__((naked)) void aps5_return(void) {
    __asm__ volatile(
        "pushfq\n\t"
        "pushq %rax\n\t pushq %rcx\n\t pushq %rdx\n\t pushq %rsi\n\t pushq %rdi\n\t"
        "pushq %r8\n\t pushq %r9\n\t pushq %r10\n\t pushq %r11\n\t"
        "pushq %rbx\n\t pushq %rbp\n\t pushq %r12\n\t pushq %r13\n\t pushq %r14\n\t pushq %r15\n\t"
        "subq $520, %rsp\n\t"
        "movups %xmm0, 8(%rsp)\n\t movups %xmm1, 24(%rsp)\n\t movups %xmm2, 40(%rsp)\n\t movups %xmm3, 56(%rsp)\n\t"
        "movups %xmm4, 72(%rsp)\n\t movups %xmm5, 88(%rsp)\n\t movups %xmm6, 104(%rsp)\n\t movups %xmm7, 120(%rsp)\n\t"
        "movups %xmm8, 136(%rsp)\n\t movups %xmm9, 152(%rsp)\n\t movups %xmm10, 168(%rsp)\n\t movups %xmm11, 184(%rsp)\n\t"
        "movups %xmm12, 200(%rsp)\n\t movups %xmm13, 216(%rsp)\n\t movups %xmm14, 232(%rsp)\n\t movups %xmm15, 248(%rsp)\n\t"
        "vextractf128 $1, %ymm0, 264(%rsp)\n\t vextractf128 $1, %ymm1, 280(%rsp)\n\t"
        "vextractf128 $1, %ymm2, 296(%rsp)\n\t vextractf128 $1, %ymm3, 312(%rsp)\n\t"
        "vextractf128 $1, %ymm4, 328(%rsp)\n\t vextractf128 $1, %ymm5, 344(%rsp)\n\t"
        "vextractf128 $1, %ymm6, 360(%rsp)\n\t vextractf128 $1, %ymm7, 376(%rsp)\n\t"
        "vextractf128 $1, %ymm8, 392(%rsp)\n\t vextractf128 $1, %ymm9, 408(%rsp)\n\t"
        "vextractf128 $1, %ymm10, 424(%rsp)\n\t vextractf128 $1, %ymm11, 440(%rsp)\n\t"
        "vextractf128 $1, %ymm12, 456(%rsp)\n\t vextractf128 $1, %ymm13, 472(%rsp)\n\t"
        "vextractf128 $1, %ymm14, 488(%rsp)\n\t vextractf128 $1, %ymm15, 504(%rsp)\n\t"
        "movq %rsp, %rdi\n\t"
        "callq _aps5_record_return\n\t"
        "movq %rax, 0(%rsp)\n\t"
        "movups 8(%rsp), %xmm0\n\t movups 24(%rsp), %xmm1\n\t movups 40(%rsp), %xmm2\n\t movups 56(%rsp), %xmm3\n\t"
        "movups 72(%rsp), %xmm4\n\t movups 88(%rsp), %xmm5\n\t movups 104(%rsp), %xmm6\n\t movups 120(%rsp), %xmm7\n\t"
        "movups 136(%rsp), %xmm8\n\t movups 152(%rsp), %xmm9\n\t movups 168(%rsp), %xmm10\n\t movups 184(%rsp), %xmm11\n\t"
        "movups 200(%rsp), %xmm12\n\t movups 216(%rsp), %xmm13\n\t movups 232(%rsp), %xmm14\n\t movups 248(%rsp), %xmm15\n\t"
        "vinsertf128 $1, 264(%rsp), %ymm0, %ymm0\n\t vinsertf128 $1, 280(%rsp), %ymm1, %ymm1\n\t"
        "vinsertf128 $1, 296(%rsp), %ymm2, %ymm2\n\t vinsertf128 $1, 312(%rsp), %ymm3, %ymm3\n\t"
        "vinsertf128 $1, 328(%rsp), %ymm4, %ymm4\n\t vinsertf128 $1, 344(%rsp), %ymm5, %ymm5\n\t"
        "vinsertf128 $1, 360(%rsp), %ymm6, %ymm6\n\t vinsertf128 $1, 376(%rsp), %ymm7, %ymm7\n\t"
        "vinsertf128 $1, 392(%rsp), %ymm8, %ymm8\n\t vinsertf128 $1, 408(%rsp), %ymm9, %ymm9\n\t"
        "vinsertf128 $1, 424(%rsp), %ymm10, %ymm10\n\t vinsertf128 $1, 440(%rsp), %ymm11, %ymm11\n\t"
        "vinsertf128 $1, 456(%rsp), %ymm12, %ymm12\n\t vinsertf128 $1, 472(%rsp), %ymm13, %ymm13\n\t"
        "vinsertf128 $1, 488(%rsp), %ymm14, %ymm14\n\t vinsertf128 $1, 504(%rsp), %ymm15, %ymm15\n\t"
        "addq $520, %rsp\n\t"
        "popq %r15\n\t popq %r14\n\t popq %r13\n\t popq %r12\n\t popq %rbp\n\t popq %rbx\n\t"
        "popq %r11\n\t popq %r10\n\t popq %r9\n\t popq %r8\n\t popq %rdi\n\t popq %rsi\n\t popq %rdx\n\t popq %rcx\n\t popq %rax\n\t"
        "popfq\n\t"
        "movq -648(%rsp), %r11\n\t"
        "movq %r11, -8(%rsp)\n\t"
        "movq -80(%rsp), %r11\n\t"
        "subq $8, %rsp\n\t"
        "retq\n\t");
}

static void dump_records(const char* path) {
    FILE* out = fopen(path, "wb");
    if (!out) return;
    uint32_t count = (uint32_t)g_record_count;
    fwrite(&count, 4, 1, out);
    for (int index = 0; index < g_record_count; ++index) {
        struct record* r = &g_records[index];
        fwrite(&r->site, 8, 1, out); fwrite(&r->target, 8, 1, out);
        fwrite(&r->tail, 8, 1, out); fwrite(&r->seq, 8, 1, out);
        fwrite(&r->arg_rsp, 8, 1, out);
        fwrite(r->arg_gprs, 8, 16, out);
        fwrite(r->arg_xmm, 1, 256, out);
        fwrite(&r->ret_flags, 8, 1, out);
        fwrite(&r->completed, 4, 1, out);
        fwrite(r->ret_gprs, 8, 16, out);
        fwrite(r->ret_xmm, 1, 256, out);
        fwrite(r->ret_ymm, 1, 256, out);
        if (r->pre) fwrite(r->pre, 1, SNAP_SIZE, out); else { char* z = (char*)calloc(SNAP_SIZE, 1); fwrite(z, 1, SNAP_SIZE, out); free(z); }
        if (r->post) fwrite(r->post, 1, SNAP_SIZE, out); else { char* z = (char*)calloc(SNAP_SIZE, 1); fwrite(z, 1, SNAP_SIZE, out); free(z); }
    }
    fclose(out);
}

int main(int argc, char** argv) {
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGILL, &sa, 0); sigaction(SIGSEGV, &sa, 0); sigaction(SIGBUS, &sa, 0); sigaction(SIGFPE, &sa, 0);
    uint64_t address = strtoull(argv[2], 0, 16);
    FILE* segments = fopen(argv[1], "rb");
    uint32_t count = 0;
    if (fread(&count, 4, 1, segments) != 1) return 2;
    if (count > 64) return 2;
    /* Read every segment into memory first, then map the union range once: several functions can
       share a 4 KiB page, and mapping each segment separately with MAP_FIXED would discard the
       bytes already written for its page neighbours. */
    struct { uint64_t vaddr, filesz, memsz; unsigned char* data; } segs[64];
    uint64_t lo = ~0ULL, hi = 0;
    for (uint32_t index = 0; index < count; ++index) {
        uint64_t vaddr, filesz, memsz;
        if (fread(&vaddr,8,1,segments)!=1||fread(&filesz,8,1,segments)!=1||fread(&memsz,8,1,segments)!=1) return 2;
        segs[index].vaddr = vaddr; segs[index].filesz = filesz; segs[index].memsz = memsz;
        segs[index].data = filesz ? (unsigned char*)malloc(filesz) : 0;
        if (filesz && fread(segs[index].data, 1, filesz, segments) != (size_t)filesz) return 4;
        uint64_t start = vaddr & ~0xfffull;
        uint64_t end = (vaddr + (memsz > filesz ? memsz : filesz) + 0xfffull) & ~0xfffull;
        if (start < lo) lo = start;
        if (end > hi) hi = end;
    }
    if (hi <= lo) return 2;
    void* image = mmap((void*)(BASE + lo), hi - lo, 7, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (image == MAP_FAILED) return 3;
    for (uint32_t index = 0; index < count; ++index) {
        if (segs[index].filesz) memcpy((char*)image + (segs[index].vaddr - lo), segs[index].data, segs[index].filesz);
    }
    if (mprotect((void*)(BASE + (address & ~0xfffull)), 0x1000, 7) != 0) return 5;
    struct regs in, out;
    mmap((void*)(BASE+0x70000000), 0x100000, 3, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    void* scratch = mmap((void*)(BASE + 0x60000000), 0x100000, 3, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (scratch == MAP_FAILED) return 8;
    FILE* pages = fopen(argv[5], "rb");
    if (pages) { if (fread((void*)(BASE + 0x60000000), 1, 0x10000, pages) != 0x10000) return 9; fclose(pages); }
    FILE* input = fopen(argv[3], "rb");
    if (fread(&in, 1, sizeof(in), input) != sizeof(in)) return 6;
    memset(&out, 0, sizeof(out));
    if (argc > 6) {
        void* island = mmap((void*)(BASE + ISLAND_OFFSET), 0x100000, 7,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        FILE* sites = fopen(argv[6], "rb");
        if (sites && island != MAP_FAILED) {
            uint32_t n = 0;
            if (fread(&n, 4, 1, sites) == 1) {
                for (uint32_t i = 0; i < n && i < 4096; ++i) {
                    uint64_t retaddr, target, tail;
                    if (fread(&retaddr,8,1,sites)!=1||fread(&target,8,1,sites)!=1||fread(&tail,8,1,sites)!=1) break;
                    g_site_retaddr[g_site_count] = retaddr;
                    g_site_target[g_site_count] = target;
                    g_site_tail[g_site_count] = tail;
                    g_site_count++;
                    /* The runner's own text may be out of rel32 range of the guest image, so each
                       site calls a nearby island stub that jumps to the trampoline absolutely. */
                    unsigned char* stub = (unsigned char*)island + 16u * i;
                    uint64_t entry = (uint64_t)(tail ? (void*)aps5_entry_tail : (void*)aps5_entry);
                    stub[0] = 0x49; stub[1] = 0xBB;
                    memcpy(stub + 2, &entry, 8);
                    stub[10] = 0x41; stub[11] = 0xFF; stub[12] = 0xE3;
                }
            }
            fclose(sites);
        }
    }
    __asm__ volatile("vzeroall" ::: "memory");
    __asm__ volatile("fninit" ::: "memory");
    invoke((void*)(BASE + address), &in, &out, (uint64_t*)(BASE + 0x70080000), 0x10000);
    unsigned char fx[512] __attribute__((aligned(16)));
    __asm__ volatile("fxsave %0" : "=m"(fx));
    unsigned char ymm[16][16] __attribute__((aligned(16)));
    #define Y(i) __asm__ volatile("vextractf128 $1, %%ymm" #i ", %0" : "=m"(ymm[i]));
    Y(0) Y(1) Y(2) Y(3) Y(4) Y(5) Y(6) Y(7) Y(8) Y(9) Y(10) Y(11) Y(12) Y(13) Y(14) Y(15)
    uint64_t flags; __asm__ volatile("pushfq\n popq %0" : "=r"(flags));
    FILE* output = fopen(argv[4], "wb");
    fwrite(&out, 1, sizeof(out), output);
    fwrite(&flags, 1, 8, output);
    fwrite(fx, 1, 512, output);
    fwrite(ymm, 1, 256, output);
    fwrite((void*)(BASE + 0x60000000), 1, 0x10000, output);
    fclose(output); fclose(input); fclose(segments);
    if (argc > 7) dump_records(argv[7]);
    return 0;
}
"""


# --------------------------------------------------------------------------------------------------
# Site discovery and the recording run
# --------------------------------------------------------------------------------------------------

def _decoder():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    return decoder, X86_OP_IMM


def find_sites(title, sizes, address):
    """Direct `call rel32` and tail `jmp rel32` sites in the function at `address`.

    A target whose bytes are a PLT stub (`ff 25`) is an import and cannot be executed in the
    synthetic image (its GOT slot is zero), so it is left for the compiler to reject.
    """
    decoder, X86_OP_IMM = _decoder()
    size = sizes[address]
    code = title.code(address, size)
    if code is None:
        return []
    sites = []
    for ins in decoder.disasm(code, address):
        if ins.mnemonic not in ('call', 'jmp') or not ins.operands or ins.operands[0].type != X86_OP_IMM:
            continue
        target = ins.operands[0].imm
        if target in sizes and title.code(target, 2) and title.code(target, 2)[:2] == b'\xff\x25':
            continue
        tail = 1 if ins.mnemonic == 'jmp' else 0
        if tail and address <= target < address + size:
            continue  # a local branch, not a tail call
        if not tail and ins.address == address:
            continue
        sites.append({'site': ins.address, 'target': target, 'tail': tail})
    return sites


def _build_runner(directory):
    source = directory / "recorder.c"
    source.write_text(RECORDER_C)
    binary = directory / "recorder"
    if not binary.exists():
        subprocess.run(["xcrun", "clang", "-arch", "x86_64", "-O1", "-mavx", str(source), "-o", str(binary)],
                       check=True, capture_output=True)
    return binary


def parse_records(path):
    data = Path(path).read_bytes()
    count, = struct.unpack_from("<I", data, 0)
    offset = 4
    records = []
    for _ in range(count):
        site, target, tail, seq, arg_rsp = struct.unpack_from("<5Q", data, offset); offset += 40
        arg_gprs = list(struct.unpack_from("<16Q", data, offset)); offset += 128
        arg_xmm = data[offset:offset + 256]; offset += 256
        ret_flags, = struct.unpack_from("<Q", data, offset); offset += 8
        completed, = struct.unpack_from("<i", data, offset); offset += 4
        ret_gprs = list(struct.unpack_from("<16Q", data, offset)); offset += 128
        ret_xmm = data[offset:offset + 256]; offset += 256
        ret_ymm = data[offset:offset + 256]; offset += 256
        pre = data[offset:offset + SNAP_SIZE]; offset += SNAP_SIZE
        post = data[offset:offset + SNAP_SIZE]; offset += SNAP_SIZE
        records.append({'site': site, 'target': target, 'tail': tail, 'seq': seq, 'arg_rsp': arg_rsp,
                        'arg_gprs': arg_gprs, 'arg_xmm': arg_xmm, 'ret_flags': ret_flags,
                        'completed': completed, 'ret_gprs': ret_gprs, 'ret_xmm': ret_xmm,
                        'ret_ymm': ret_ymm, 'pre': pre, 'post': post})
    return records


def memory_diff(pre, post):
    """Contiguous runs of changed bytes as (guest address, bytes)."""
    runs = []
    index = 0
    limit = len(pre)
    while index < limit:
        if pre[index] == post[index]:
            index += 1
            continue
        start = index
        while index < limit and pre[index] != post[index]:
            index += 1
        address = SCRATCH + start if start < SCRATCH_SIZE else STACK_SNAP + (start - SCRATCH_SIZE)
        runs.append((address, bytes(post[start:index])))
    return runs


# --------------------------------------------------------------------------------------------------
# Driver: record the calls of one function, and turn the records into ARM replay stubs
# --------------------------------------------------------------------------------------------------

def bake_sites(image, address, sites):
    """Copy `image` with each site redirected to its island stub.

    `image` must have the function under test as its first PT_LOAD code segment (the layout
    `difftest.build_synthetic` produces when `functions[0]` is the root), so the function's bytes
    start at file offset 0x1000. The call displacement is baked in here rather than written at
    run time: Rosetta 2 does not reliably execute a guest page that is rewritten after it has been
    mapped.
    """
    patched = bytearray(image)
    for index, site in enumerate(sites):
        offset = 0x1000 + (site['site'] - address)
        displacement = struct.pack('<i', ISLAND + 16 * index - (BASE + site['site'] + 5))
        patched[offset] = 0xE9 if site['tail'] else 0xE8
        patched[offset + 1:offset + 5] = displacement
    return bytes(patched)


def record_calls(title, sizes, address, sites, registers, memory, directory):
    """Run the function on the x86 side with `sites` redirected, return (records, out_bytes).

    `out_bytes` is the same final-state blob `full_state.RUNNER` writes, so the caller can reuse
    `full_state.compare`. Raises RuntimeError when the x86 side faults.
    """
    import difftest as harness
    import replay
    functions = harness.closure(title, sizes, address, 200)
    functions = [address] + [item for item in functions if item != address]
    codes = [(item, title.code(item, sizes[item])) for item in functions]
    codes = [(item, code) for item, code in codes if code]
    referenced = {}
    for item, code in codes:
        for target, size in harness.references(code, item).items():
            referenced[target] = max(referenced.get(target, 1), size)
    image, _contracts = harness.build_synthetic(codes, referenced, uniform=True)
    image = bake_sites(image, address, sites)
    (directory / "segments.bin").write_bytes(_segment_blob(image))
    (directory / "case.bin").write_bytes(
        b"".join(int(registers.get(name, 0)).to_bytes(8, "little") for name in replay.REGISTERS))
    (directory / "pages.bin").write_bytes(memory)
    site_blob = struct.pack("<I", len(sites))
    for site in sites:
        site_blob += struct.pack("<QQQ", BASE + site['site'] + 5, BASE + site['target'], site['tail'])
    (directory / "sites.bin").write_bytes(site_blob)
    runner = _build_runner(directory)
    completed = subprocess.run([str(runner), str(directory / "segments.bin"), hex(address),
                                str(directory / "case.bin"), str(directory / "out.bin"),
                                str(directory / "pages.bin"), str(directory / "sites.bin"),
                                str(directory / "records.bin")], capture_output=True, timeout=120)
    if completed.returncode != 0:
        raise RuntimeError(f"x86 recorder exit {completed.returncode}: {completed.stderr[-200:]!r}")
    return parse_records(directory / "records.bin"), (directory / "out.bin").read_bytes()


def _segment_blob(image):
    import io
    import replay
    stream = io.BytesIO()
    entries = replay.elf_segments(image)
    stream.write(struct.pack("<I", len(entries)))
    for vaddr, filesz, memsz, data in entries:
        stream.write(struct.pack("<QQQ", vaddr, filesz, memsz))
        stream.write(data)
    return stream.getvalue()


def _c_bytes(data):
    return "".join("\\%03o" % byte for byte in data)


def replay_stub_source(records, callees):
    """C source defining one `void sub_X(void* rf)` per callee that replays the recorded calls.

    Records for a callee are replayed in call order; a stub that is called more times than it was
    recorded leaves the register file untouched, which is the honest "no evidence" outcome.
    """
    by_target = {}
    for record in records:
        if record['completed']:
            by_target.setdefault(record['target'] - BASE, []).append(record)
    lines = ["#include <string.h>", "typedef unsigned long long u64;", "typedef unsigned char u8;"]
    for target in sorted(callees):
        recorded = by_target.get(target, [])
        lines.append(f"void sub_{target:x}(void* rf) {{")
        lines.append("  static int counter;")
        lines.append("  int index = counter++;")
        lines.append("  u64* g = (u64*)rf;")
        for index, record in enumerate(recorded):
            lines.append(f"  if (index == {index}) {{")
            for lane, value in enumerate(record['ret_gprs']):
                if lane == 4:  # rsp is not reloaded from the callee by the AOT caller
                    continue
                lines.append(f"    g[{lane}] = {value}ULL;")
            for base, blob in ((128, record['ret_xmm']), (384, record['ret_ymm'])):
                for lane in range(16):
                    chunk = blob[lane * 16:lane * 16 + 16]
                    lines.append(f'    memcpy((u8*)rf + {base + lane * 16}, "{_c_bytes(chunk)}", 16);')
            for run_address, run in memory_diff(record['pre'], record['post']):
                for start in range(0, len(run), 16):
                    chunk = run[start:start + 16]
                    lines.append(f'    memcpy((void*)(u64)({run_address + start}ULL), "{_c_bytes(chunk)}", {len(chunk)});')
            lines.append("    return;")
            lines.append("  }")
        lines.append("}")
    return "\n".join(lines) + "\n"
