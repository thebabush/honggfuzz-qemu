#ifndef FUZZ_HONGGFUZZ_H
#define FUZZ_HONGGFUZZ_H

#pragma push_macro("linux")
#undef linux
#include <honggfuzz.h>
#pragma pop_macro("linux")

#include <libhfcommon/util.h>
#include <libhfcommon/log.h>

extern abi_ulong honggfuzz_qemu_entry_point;
extern abi_ulong honggfuzz_qemu_start_code;
extern abi_ulong honggfuzz_qemu_end_code;

extern void honggfuzz_qemu_setup(void);

extern uint32_t my_thread_no;
extern feedback_t* feedback;

static inline void honggfuzz_qemu_trace_pc(abi_ulong pc) {

  if (pc > honggfuzz_qemu_end_code || pc < honggfuzz_qemu_start_code)
    return;

  // TODO(babush): use a better hashing strategy
  pc = (pc >> 4) ^ (pc << 8);

  register uintptr_t ret = (uintptr_t)pc & _HF_PERF_BITMAP_BITSZ_MASK;
  register uint8_t  prev = ATOMIC_BTS(feedback->bbMapPc, ret);
  if (!prev) {
    ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
  }

}


#endif
