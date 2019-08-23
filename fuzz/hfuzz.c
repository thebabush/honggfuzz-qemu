#include <stdio.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg-op.h"

#include "fuzz/hfuzz.h"


#define HFUZZ_QEMU_TESTCASE_PATH_TMPL "/tmp/hfq-XXXXXX"

#define ck_write(fd, buf, len) do { \
    size_t _len = (len); \
    size_t _res = write(fd, buf, _len); \
    if (_res != _len) { fputs("Short write to testcase\n", stderr); } \
  } while (0)

static int hfuzz_qemu_testcase_fd = -1;

static char *hfuzz_qemu_create_testcase(void) {
  if (hfuzz_qemu_testcase_fd != -1) {
    fputs("hfuzz_qemu_create_testcase() called two times :/\n", stderr);
    exit(1);
  }

  char *ptr = (char*)malloc(sizeof(HFUZZ_QEMU_TESTCASE_PATH_TMPL));
  if (!ptr) {
    perror("hfuzz_qemu_create_testcase: ");
    exit(1);
  }

  strcpy(ptr, HFUZZ_QEMU_TESTCASE_PATH_TMPL);
  int fd = mkstemp(ptr);
  if (fd < 0) {
    perror("hfuzz_qemu_create_testcase: ");
    exit(1);
  }

  hfuzz_qemu_testcase_fd = fd;
  return ptr;
}

void hfuzz_qemu_handle_argv(char **argv) {
  while (*argv != NULL) {
    if (strcmp(*argv, "___FILE___") == 0) {
      *argv = hfuzz_qemu_create_testcase();
    }
    ++argv;
  }
}

static void write_testcase(const uint8_t *buff, size_t len) {
  lseek(hfuzz_qemu_testcase_fd, 0, SEEK_SET);
  ck_write(hfuzz_qemu_testcase_fd, buff, len);
  if (ftruncate(hfuzz_qemu_testcase_fd, len) < 0) {
    perror("ftruncate: ");
    exit(1);
  }
  lseek(hfuzz_qemu_testcase_fd, 0, SEEK_SET);
}

extern void HonggfuzzFetchData(const uint8_t** buf_ptr, size_t* len_ptr);

static void fork_server(void) {
  while (2) {
    pid_t pid = fork();

    if (pid < 0) {
      fputs("fork error\n", stderr);
      exit(1);
    }

    size_t len;
    const uint8_t* buf;
    HonggfuzzFetchData(&buf, &len);
    write_testcase(buf, len);

    if (!pid) {
      // Child
      return;
    }

    // Parent
    int status;
    if (waitpid(pid, &status, 0) <= 0) {
      fputs("waitpid error\n", stderr);
      exit(1);
    }
  }
}

extern void hfuzzInstrumentInit(void);

void hfuzz_qemu_setup(void) {
  rcu_disable_atfork();
  hfuzzInstrumentInit();

  if (getenv("HFUZZ_INST_LIBS")) {
    hfuzz_qemu_start_code = 0;
    hfuzz_qemu_end_code   = (abi_ulong)-1;
  }

  if (hfuzz_qemu_testcase_fd != -1) {
    fork_server();
  }
}

extern void hfuzz_trace_cmp4(uintptr_t pc, uint64_t Arg1, uint64_t Arg2);
extern void hfuzz_trace_cmp8(uintptr_t pc, uint64_t Arg1, uint64_t Arg2);

void HELPER(hfuzz_qemu_trace_cmp_i64)(
        uint64_t cur_loc, uint64_t arg1, uint64_t arg2
    ) {
  hfuzz_trace_cmp8(cur_loc, arg1, arg2);
}

void HELPER(hfuzz_qemu_trace_cmp_i32)(
        uint32_t cur_loc, uint32_t arg1, uint32_t arg2
    ) {
  hfuzz_trace_cmp4(cur_loc, arg1, arg2);
}

