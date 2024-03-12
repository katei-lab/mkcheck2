#ifndef __EXECSNOOP_H__
#define __EXECSNOOP_H__

#if __swift__
#  include <bpf/bpf.h>
#  include <linux/limits.h>
#  include <linux/types.h>
#  include <stdint.h>
#  include <sys/types.h>
#else
#  include "vmlinux.h"
#  define PATH_MAX 4096
#endif

#ifndef AT_FDCWD
#  define AT_FDCWD -100
#endif

#ifndef S_IFIFO
#  define S_IFIFO 0010000
#endif

#ifndef MAP_SHARED
#  define MAP_SHARED 0x01
#endif

#ifndef PROT_WRITE
#  define PROT_WRITE 0x02
#endif

#define DEFAULT_SUB_BUF_SIZE 256 // Max filename length in Linux.
#define DEFAULT_SUB_BUF_LEN 16

enum mkcheck2_event_type : int {
  kEventTypeExec = 1,
  kEventTypeExit = 2,
  kEventTypeInput = 4,
  kEventTypeOutput = 5,
  kEventTypeRemove = 6,
  kEventTypeRename = 7,
  kEventTypeChdir = 8,
  kEventTypeClone = 9,
  kEventTypeInputAt = 10,
  kEventTypeOutputAt = 11,
  kEventTypeLink = 12,
  kEventTypeSymlink = 13,
  kEventTypeRemoveAt = 14,
  kEventTypeLinkAt = 15,
  kEventTypeRenameAt = 16,
  kEventTypeSymlinkAt = 17,
  kEventTypeExecAt = 18,
} __attribute__((enum_extensibility(closed)));

typedef char mkcheck2_path_t[DEFAULT_SUB_BUF_LEN][DEFAULT_SUB_BUF_SIZE];

struct mkcheck2_event_header {
  int _type;
  pid_t pid;
  uint64_t uid;
  int source_line;
};

struct mkcheck2_event {
  struct mkcheck2_event_header header;
  int payload;
  mkcheck2_path_t path;
};

struct mkcheck2_fat_event {
  struct mkcheck2_event_header header;
  int payload;
  mkcheck2_path_t path[2];
};

struct mkcheck2_fat2_event {
  struct mkcheck2_event_header header;
  mkcheck2_path_t path[4];
};

static inline void mkcheck2_path_clone(mkcheck2_path_t dst, const mkcheck2_path_t src) {
  for (int i = 0; i < DEFAULT_SUB_BUF_LEN; i++) {
    // Bulk copy for each 8-byte word.
    for (int j = 0; j < DEFAULT_SUB_BUF_SIZE; j += 8) {
      *(uint64_t *)(dst[i] + j) = *(uint64_t *)(src[i] + j);
    }
  }
}

static inline void mkcheck2_event_clone(struct mkcheck2_event *dst, const struct mkcheck2_event *src) {
  dst->header = src->header;
  mkcheck2_path_clone(dst->path, src->path);
  dst->payload = src->payload;
}

static inline void mkcheck2_fat_event_clone(struct mkcheck2_fat_event *dst, const struct mkcheck2_fat_event *src) {
  dst->header = src->header;
  dst->payload = src->payload;
  mkcheck2_path_clone(dst->path[0], src->path[0]);
  mkcheck2_path_clone(dst->path[1], src->path[1]);
}

static inline void mkcheck2_fat2_event_clone(struct mkcheck2_fat2_event *dst, const struct mkcheck2_fat2_event *src) {
  dst->header = src->header;
  mkcheck2_path_clone(dst->path[0], src->path[0]);
  mkcheck2_path_clone(dst->path[1], src->path[1]);
  mkcheck2_path_clone(dst->path[2], src->path[2]);
  mkcheck2_path_clone(dst->path[3], src->path[3]);
}

enum mkcheck2_error_type : int {
  kErrorRingBufferFull = 1,
  kErrorStagingEventFull = 2,
  kErrorStagingEventNotAllocated = 3,
  kErrorReadUserStr = 4,
  kErrorReadDentryStr = 5,
  kErrorStagingConflict = 6,
} __attribute__((enum_extensibility(closed)));

struct mkcheck2_error {
  // XXX: Use of 'enum mkcheck2_error_type' leads invalid BTF type encoding
  // for some reason, so we use 'int' instead.
  int type;
  // The line number in the BPF program where the error occurred.
  int line;
};

#endif /* __EXECSNOOP_H__ */
