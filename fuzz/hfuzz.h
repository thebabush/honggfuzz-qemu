#ifndef FUZZ_HONGGFUZZ_H
#define FUZZ_HONGGFUZZ_H

#include "fuzz/config.h"

extern abi_ulong hfuzz_qemu_entry_point;
extern abi_ulong hfuzz_qemu_start_code;
extern abi_ulong hfuzz_qemu_end_code;

extern void hfuzz_qemu_setup(void);

extern void hfuzz_trace_pc(uintptr_t pc);

static inline void hfuzz_qemu_trace_pc(abi_ulong pc) {
  if (pc > hfuzz_qemu_end_code || pc < hfuzz_qemu_start_code) {
    return;
  }
  hfuzz_trace_pc(pc);
}

#ifdef HFUZZ_FORKSERVER
extern void hfuzz_qemu_handle_argv(char **argv);
#endif // HFUZZ_FORKSERVER

#endif
