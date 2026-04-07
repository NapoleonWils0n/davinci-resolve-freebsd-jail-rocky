#define _GNU_SOURCE

#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define NV_UVM_INITIALIZE   0x30000001
#define NV_UVM_DEINITIALIZE 0x30000002
#define NV_ERR_NOT_SUPPORTED 0x56

struct NvUvmInitParams
{
  uint64_t flags __attribute__((aligned(8)));
  uint32_t status;
};

// ioctl interception - unchanged from shkhln's original

int (*libc_ioctl)(int fd, unsigned long request, ...) = NULL;

int ioctl(int fd, unsigned long request, ...) {
  if (!libc_ioctl) libc_ioctl = dlsym(RTLD_NEXT, "ioctl");

  va_list _args_;
  va_start(_args_, request);
  void* data = va_arg(_args_, void*);
  va_end(_args_);

  if (request == NV_UVM_INITIALIZE) {
    struct NvUvmInitParams* params = (struct NvUvmInitParams*)data;
    params->status = NV_ERR_NOT_SUPPORTED;
    return 0;
  }
  if (request == NV_UVM_DEINITIALIZE) return 0;

  return libc_ioctl(fd, request, data);
}

// path checks

static int is_nvidia_uvm(const char* path) {
  return path && strcmp("/dev/nvidia-uvm", path) == 0;
}

static int is_proc_task_comm(const char* path) {
  if (!path) return 0;
  if (strncmp(path, "/proc/self/task/", 16) != 0) return 0;
  char* tail = strchr(path + 16, '/');
  return (tail != NULL && strcmp(tail, "/comm") == 0);
}

// open() - the original hook, still needed as fallback

int (*libc_open)(const char* path, int flags, ...) = NULL;

int open(const char* path, int flags, ...) {
  if (!libc_open) libc_open = dlsym(RTLD_NEXT, "open");

  mode_t mode = 0;
  va_list _args_;
  va_start(_args_, flags);
  if (flags & O_CREAT) mode = va_arg(_args_, int);
  va_end(_args_);

  if (is_nvidia_uvm(path) || is_proc_task_comm(path))
    return libc_open("/dev/null", flags, mode);
  return libc_open(path, flags, mode);
}

// open64()

int (*libc_open64)(const char* path, int flags, ...) = NULL;

int open64(const char* path, int flags, ...) {
  if (!libc_open64) libc_open64 = dlsym(RTLD_NEXT, "open64");

  mode_t mode = 0;
  va_list _args_;
  va_start(_args_, flags);
  if (flags & O_CREAT) mode = va_arg(_args_, int);
  va_end(_args_);

  if (is_nvidia_uvm(path) || is_proc_task_comm(path))
    return libc_open64("/dev/null", flags, mode);
  return libc_open64(path, flags, mode);
}

// openat() - this is the important one, glibc 2.34+ uses this for everything

int (*libc_openat)(int dirfd, const char* path, int flags, ...) = NULL;

int openat(int dirfd, const char* path, int flags, ...) {
  if (!libc_openat) libc_openat = dlsym(RTLD_NEXT, "openat");

  mode_t mode = 0;
  va_list _args_;
  va_start(_args_, flags);
  if (flags & O_CREAT) mode = va_arg(_args_, int);
  va_end(_args_);

  if (is_nvidia_uvm(path) || is_proc_task_comm(path))
    return libc_openat(dirfd, "/dev/null", flags, mode);
  return libc_openat(dirfd, path, flags, mode);
}

// openat64()

int (*libc_openat64)(int dirfd, const char* path, int flags, ...) = NULL;

int openat64(int dirfd, const char* path, int flags, ...) {
  if (!libc_openat64) libc_openat64 = dlsym(RTLD_NEXT, "openat64");

  mode_t mode = 0;
  va_list _args_;
  va_start(_args_, flags);
  if (flags & O_CREAT) mode = va_arg(_args_, int);
  va_end(_args_);

  if (is_nvidia_uvm(path) || is_proc_task_comm(path))
    return libc_openat64(dirfd, "/dev/null", flags, mode);
  return libc_openat64(dirfd, path, flags, mode);
}

// fopen() - for /proc/self/task/*/comm writes on 570+ drivers

FILE* (*libc_fopen)(const char* path, const char* mode) = NULL;

FILE* fopen(const char* path, const char* mode) {
  if (!libc_fopen) libc_fopen = dlsym(RTLD_NEXT, "fopen");
  if (is_proc_task_comm(path)) return libc_fopen("/dev/null", mode);
  return libc_fopen(path, mode);
}

FILE* (*libc_fopen64)(const char* path, const char* mode) = NULL;

FILE* fopen64(const char* path, const char* mode) {
  if (!libc_fopen64) libc_fopen64 = dlsym(RTLD_NEXT, "fopen64");
  if (is_proc_task_comm(path)) return libc_fopen64("/dev/null", mode);
  return libc_fopen64(path, mode);
}
