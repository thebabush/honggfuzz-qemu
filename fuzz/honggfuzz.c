#include <stdio.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg-op.h"

#include "fuzz/honggfuzz.h"

uint32_t my_thread_no = 0;
static feedback_t bbMapFb;
feedback_t* feedback = &bbMapFb;


static void instrumentClearNewCov(void) {
    feedback->pidFeedbackPc[my_thread_no] = 0U;
    feedback->pidFeedbackEdge[my_thread_no] = 0U;
    feedback->pidFeedbackCmp[my_thread_no] = 0U;
}

void honggfuzz_qemu_setup(void) {

  rcu_disable_atfork();

  char* my_thread_no_str = getenv(_HF_THREAD_NO_ENV);
  if (my_thread_no_str == NULL) {
    LOG_D("The '%s' envvar is not set", _HF_THREAD_NO_ENV);
    return;
  }
  my_thread_no = atoi(my_thread_no_str);

  if (my_thread_no >= _HF_THREAD_MAX) {
    LOG_F("Received (via envvar) my_thread_no > _HF_THREAD_MAX (%" PRIu32 " > %d)\n",
        my_thread_no, _HF_THREAD_MAX);
  }

  struct stat st;
  if (fstat(_HF_BITMAP_FD, &st) == -1) {
      return;
  }
  if (st.st_size != sizeof(feedback_t)) {
      LOG_F(
          "size of the feedback structure mismatch: st.size != sizeof(feedback_t) (%zu != %zu). "
          "Link your fuzzed binaries with the newest honggfuzz sources via hfuzz-clang(++)",
          (size_t)st.st_size, sizeof(feedback_t));
  }
  if ((feedback = mmap(NULL, sizeof(feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED,
           _HF_BITMAP_FD, 0)) == MAP_FAILED) {
      PLOG_F("mmap(fd=%d, size=%zu) of the feedback structure failed", _HF_BITMAP_FD,
          sizeof(feedback_t));
  }

  /* Reset coverage counters to their initial state */
  instrumentClearNewCov();
}

void HELPER(honggfuzz_qemu_trace_cmp_i64)(
        uint64_t cur_loc, uint64_t arg1, uint64_t arg2
    ) {
  uintptr_t pos = (uintptr_t)cur_loc % _HF_PERF_BITMAP_SIZE_16M;
  register uint8_t v = ((sizeof(arg1) * 8) - __builtin_popcountll(arg1 ^ arg2));
  uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
  if (prev < v) {
    ATOMIC_SET(feedback->bbMapCmp[pos], v);
    ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
  }
}

