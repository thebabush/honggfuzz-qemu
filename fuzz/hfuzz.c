#include <stdio.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg-op.h"

#include "fuzz/hfuzz.h"


#ifdef HFUZZ_FORKSERVER
#define HFUZZ_QEMU_TESTCASE_PATH_TMPL "/tmp/hfq-%08d"

#define ck_write(fd, buf, len) do { \
    size_t _len = (len); \
    size_t _res = write(fd, buf, _len); \
    if (_res != _len) { fputs("Short write to testcase\n", stderr); } \
  } while (0)

typedef enum {
  fuzz_from_stdin,
  fuzz_from_file,
} hfuzz_input_type_t;

typedef struct {
  hfuzz_input_type_t type;
  char *path;
  int   fd;
} hfuzz_input_info_t;

static hfuzz_input_info_t hfuzz_input_info = {
  .type = fuzz_from_stdin,
  .path = 0,
  .fd   = -1,
};

void hfuzz_qemu_handle_argv(char **argv) {
  int dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) {
    perror("Error opening /dev/null");
    exit(1);
  }

  if (hfuzz_input_info.path == 0) {
    const unsigned max_path = 100;
    hfuzz_input_info.path = malloc(max_path);
    int pid = getpid();
    snprintf(
        hfuzz_input_info.path,
        max_path,
        HFUZZ_QEMU_TESTCASE_PATH_TMPL,
        pid
    );
  }

  while (*argv != NULL) {
    if (strcmp(*argv, "___FILE___") == 0) {
      *argv = hfuzz_input_info.path;
      hfuzz_input_info.type = fuzz_from_file;
    }
    ++argv;
  }

  if (hfuzz_input_info.type == fuzz_from_stdin) {
    int fd = open(hfuzz_input_info.path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
      perror("Error creating file for stdin");
      exit(1);
    }
    hfuzz_input_info.fd = fd;

    // Child's stdin is our guy
    dup2(fd, 0);
  } else {
    dup2(dev_null_fd, 0);
  }

  dup2(dev_null_fd, 1);
  dup2(dev_null_fd, 2);
}

static void write_testcase(const uint8_t *buff, size_t len) {
  if (hfuzz_input_info.type == fuzz_from_file) {
    // Fuzzing from file: unlink, create, write, close
    unlink(hfuzz_input_info.path);

    int fd = open(hfuzz_input_info.path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
      perror("Error creating testcase file");
      exit(2);
    }

    ck_write(fd, buff, len);

    close(fd);
  } else {
    // Fuzzing from stdin: rewind, write, rewind
    int fd = hfuzz_input_info.fd;
    lseek(fd, 0, SEEK_SET);

    ck_write(fd, buff, len);

    if (ftruncate(fd, len) < 0) {
      perror("ftruncate");
      exit(1);
    }
    lseek(fd, 0, SEEK_SET);
  }
}

extern void HonggfuzzFetchData(const uint8_t** buf_ptr, size_t* len_ptr);

static void fork_server(void) {
  size_t len;
  const uint8_t *buf = 0;

  while (2) {
    HonggfuzzFetchData(&buf, &len);
    write_testcase(buf, len);

    pid_t pid = fork();

    if (pid < 0) {
      fputs("fork error\n", stderr);
      exit(1);
    }

    // Child
    if (!pid) {
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
#endif // HFUZZ_FORKSERVER

extern void hfuzzInstrumentInit(void);

void hfuzz_qemu_setup(void) {
  rcu_disable_atfork();
  hfuzzInstrumentInit();

  if (getenv("HFUZZ_INST_LIBS")) {
    hfuzz_qemu_start_code = 0;
    hfuzz_qemu_end_code   = (abi_ulong)-1;
  }

#ifdef HFUZZ_FORKSERVER
  fork_server();
#endif // HFUZZ_FORKSERVER
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

