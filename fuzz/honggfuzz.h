#ifndef FUZZ_HONGGFUZZ_H
#define FUZZ_HONGGFUZZ_H

extern abi_ulong honggfuzz_qemu_entry_point;
extern abi_ulong honggfuzz_qemu_start_code;
extern abi_ulong honggfuzz_qemu_end_code;

extern void honggfuzz_qemu_setup(void);

extern void hfuzz_trace_pc(uintptr_t pc);

static inline void honggfuzz_qemu_trace_pc(abi_ulong pc) {
  if (pc > honggfuzz_qemu_end_code || pc < honggfuzz_qemu_start_code) {
    return;
  }
  hfuzz_trace_pc(pc);
}


#endif
