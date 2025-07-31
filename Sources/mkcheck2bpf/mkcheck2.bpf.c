// vim: set shiftwidth=2 tabstop=2 expandtab:
#include "mkcheck2.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <linux/magic.h>
#include <linux/major.h>

#ifdef DEBUG_LOG
#  define mkcheck2_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#  define mkcheck2_debug(fmt, ...)
#endif

// Skip if path is "/proc/self/exe"
#define SKIP_PROC_SELF_EXEC(path)                                                                                      \
  do {                                                                                                                 \
    const char exe_path[] = "/proc/self/exe";                                                                          \
    char short_buffer[sizeof(exe_path)];                                                                               \
    if (bpf_core_read_user_str(short_buffer, sizeof(short_buffer), path) >= 0) {                                       \
      if (__builtin_memcmp(short_buffer, exe_path, sizeof(exe_path)) == 0) {                                           \
        return 0;                                                                                                      \
      }                                                                                                                \
    }                                                                                                                  \
  } while (0)

const volatile pid_t root_ppid = 0;

static inline u64 get_and_inc_next_uid(void) {
  static volatile u64 next_uid = 0;
  return __sync_fetch_and_add(&next_uid, 1);
}

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 16 * 1024 * 1024 /* 16 MiB */);
} events SEC(".maps");

/// Map for error reporting to userspace
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct mkcheck2_error);
} fatal_errors SEC(".maps");

__attribute__((noinline)) static void __report_fatal_error(int type, int line) {
  static u32 key = 0;
  struct mkcheck2_error error = {0};
  error.type = type;
  error.line = line;
  bpf_map_update_elem(&fatal_errors, &key, &error, BPF_ANY);
}

#define report_fatal_error(type) __report_fatal_error(type, __LINE__)

struct tracing_event_fingerprint {
  u32 ino;
  /// The type of the event that generated the fingerpr
  /// \see enum mkcheck2_event_type
  int type;
};

#define TRACING_PROCESS_INFO_FINGERPRINTS 5

struct tracing_process_info {
  /// Process identifier
  pid_t parent;
  /// Unique instance identifier
  u64 uid;
  /// The index of the next fingerprint to insert
  u32 fingerprint_index;
  /// The fingerprints of the events that have been seen recently
  struct tracing_event_fingerprint fingerprints[TRACING_PROCESS_INFO_FINGERPRINTS];
};

static inline void tracing_process_info_init(struct tracing_process_info *pinfo, pid_t parent, u64 uid) {
  *pinfo = (struct tracing_process_info){0};
  pinfo->parent = parent;
  pinfo->uid = uid;

  pinfo->fingerprint_index = 0;
  for (int i = 0; i < TRACING_PROCESS_INFO_FINGERPRINTS; i++) {
    pinfo->fingerprints[i].ino = 0;
    pinfo->fingerprints[i].type = 0;
  }
}

/// Insert a given fingerprint to the process info
/// \return true if the fingerprint was inserted, false if the fingerprint was
/// already present.
///
/// If the fingerprints array is full, the oldest fingerprint is removed.
static inline bool tracing_process_info_insert_fingerprint(struct tracing_process_info *pinfo, u32 ino,
                                                           enum mkcheck2_event_type type) {
  for (int i = 0; i < TRACING_PROCESS_INFO_FINGERPRINTS; i++) {
    if (pinfo->fingerprints[i].ino == ino && pinfo->fingerprints[i].type == type) {
      // The fingerprint is already present
      return false;
    }
  }

  if (pinfo->fingerprint_index >= TRACING_PROCESS_INFO_FINGERPRINTS) {
    pinfo->fingerprint_index = 0;
  }

  // Insert the new fingerprint
  pinfo->fingerprints[pinfo->fingerprint_index].ino = ino;
  pinfo->fingerprints[pinfo->fingerprint_index].type = type;
  pinfo->fingerprint_index++;
  return true;
}

// TODO: Replace with libbpf's hashmap.h
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, struct tracing_process_info);
} tracing_pinfo SEC(".maps");

static inline bool is_tracing_pid(pid_t pid, u64 *uid) {
  struct tracing_process_info *pinfo = bpf_map_lookup_elem(&tracing_pinfo, &pid);
  if (pinfo) {
    *uid = pinfo->uid;
    return true;
  }
  return false;
}

__attribute__((always_inline)) static inline void __init_event_header(pid_t pid, u64 uid, enum mkcheck2_event_type type,
                                                                      int line, struct mkcheck2_event_header *header) {
  header->pid = pid;
  header->uid = uid;
  header->_type = type;
  header->source_line = line;
}

#define init_event_header(pid, uid, type, header) __init_event_header(pid, uid, type, __LINE__, header)

struct mkcheck2_staging_event {
  /// 0: struct mkcheck2_event
  /// 1: struct mkcheck2_fat_event
  /// 2: struct mkcheck2_fat2_event
  char type_kind;
  union {
    struct mkcheck2_event event;
    struct mkcheck2_fat_event fat_event;
    struct mkcheck2_fat2_event fat2_event;
  } u;
};
#define MKCHECK2_STAGING_EVENT_TYPE_EVENT 0
#define MKCHECK2_STAGING_EVENT_TYPE_FAT_EVENT 1
#define MKCHECK2_STAGING_EVENT_TYPE_FAT2_EVENT 2

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, u64);
  __type(value, struct mkcheck2_staging_event);
} staging_events SEC(".maps");

static struct mkcheck2_staging_event *__staging_event_allocate_generic(void *staging_events_map, void *empty_event,
                                                                       u64 pid_tgid, int line) {
  struct mkcheck2_staging_event *event = NULL;
  int ret = bpf_map_update_elem(staging_events_map, &pid_tgid, empty_event, BPF_NOEXIST);
  if (ret != 0) {
    event = bpf_map_lookup_elem(staging_events_map, &pid_tgid);
#if DEBUG_LOG
    if (event) {
      struct mkcheck2_event_header *header;
      switch (event->type_kind) {
      case MKCHECK2_STAGING_EVENT_TYPE_EVENT:
        header = &event->u.event.header;
        break;
      case MKCHECK2_STAGING_EVENT_TYPE_FAT_EVENT:
        header = &event->u.fat_event.header;
        break;
      case MKCHECK2_STAGING_EVENT_TYPE_FAT2_EVENT:
        header = &event->u.fat2_event.header;
        break;
      default:
        header = NULL;
        break;
      }
      mkcheck2_debug("Staging event conflict for pid=%d, type=%d, line=%d", header->pid, header->_type,
                     header->source_line);
    }
#endif
    int error_type = event ? kErrorStagingConflict : kErrorStagingEventFull;
    __report_fatal_error(error_type, line);
    return NULL;
  }
  event = bpf_map_lookup_elem(staging_events_map, &pid_tgid);
  if (!event) {
    // This should never happen but just in case
    __report_fatal_error(kErrorStagingEventNotAllocated, line);
    return NULL;
  }
  return event;
}

/// Deallocate the staged event for the given pid
static inline void staging_event_deallocate(u64 pid_tgid) { bpf_map_delete_elem(&staging_events, &pid_tgid); }

static struct mkcheck2_event *__staging_event_allocate(u64 pid_tgid, int line) {
  static struct mkcheck2_staging_event empty_event = {0};
  struct mkcheck2_staging_event *event =
      __staging_event_allocate_generic(&staging_events, &empty_event, pid_tgid, line);
  if (!event)
    return NULL;
  event->type_kind = MKCHECK2_STAGING_EVENT_TYPE_EVENT;
  return &event->u.event;
}
/// Allocate an event for the given pid and stage it to be submitted later
#define staging_event_allocate(pid) __staging_event_allocate(pid, __LINE__)

static struct mkcheck2_fat_event *__staging_fat_event_allocate(u64 pid_tgid, int line) {
  static struct mkcheck2_staging_event empty_event = {0};
  struct mkcheck2_staging_event *event =
      __staging_event_allocate_generic(&staging_events, &empty_event, pid_tgid, line);
  if (!event)
    return NULL;
  event->type_kind = MKCHECK2_STAGING_EVENT_TYPE_FAT_EVENT;
  return &event->u.fat_event;
}
/// Allocate an event for the given pid and stage it to be submitted later
#define staging_fat_event_allocate(pid) __staging_fat_event_allocate(pid, __LINE__)

static struct mkcheck2_fat2_event *__staging_fat2_event_allocate(u64 pid_tgid, int line) {
  static struct mkcheck2_staging_event empty_event = {0};
  struct mkcheck2_staging_event *event =
      __staging_event_allocate_generic(&staging_events, &empty_event, pid_tgid, line);
  if (!event)
    return NULL;
  event->type_kind = MKCHECK2_STAGING_EVENT_TYPE_FAT2_EVENT;
  return &event->u.fat2_event;
}
/// Allocate an event for the given pid and stage it to be submitted later
#define staging_fat2_event_allocate(pid) __staging_fat2_event_allocate(pid, __LINE__)

/// Read the dentry strings and store them in the buffer
/// \return 0 on success, 1 on error
static inline int read_dentry_strings(struct dentry *dtryp, char buf[DEFAULT_SUB_BUF_LEN][DEFAULT_SUB_BUF_SIZE]) {
  struct dentry dtry;
  struct dentry *lastdtryp = dtryp;

  int i = 0;
  if (buf) {
    if (bpf_probe_read(&dtry, sizeof(struct dentry), dtryp) < 0)
      goto err;
    if (bpf_probe_read_str(buf[i], DEFAULT_SUB_BUF_SIZE, dtry.d_name.name) < 0)
      goto err;
    for (i = 1; i < DEFAULT_SUB_BUF_LEN; i++) {
      if (dtry.d_parent != lastdtryp) {
        lastdtryp = dtry.d_parent;
        if (bpf_probe_read(&dtry, sizeof(struct dentry), dtry.d_parent) < 0)
          goto err;
        if (bpf_probe_read_str(buf[i], DEFAULT_SUB_BUF_SIZE, dtry.d_name.name) < 0)
          goto err;
      } else
        break;
    }
  }
  return 0;
err:
  return 1;
}
static inline unsigned imajor(const struct inode *inode) {
// From linux/kdev_t.h
#define MINORBITS 20
#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
  // From linux/fs.h
  dev_t i_rdev = BPF_CORE_READ(inode, i_rdev);
  return MAJOR(i_rdev);
#undef MINORBITS
#undef MAJOR
}

static inline struct dentry *get_tracing_dentry(int fd, const struct inode **inode_out) {
  struct file **files;
  struct file *file;
  struct path f_path;
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  files = BPF_CORE_READ(task, files, fdt, fd);
  bpf_core_read(&file, sizeof(struct file *), &files[fd]);
  bpf_core_read(&f_path, sizeof(struct path), &file->f_path);
  // Check if the file is under proc
  __le16 s_magic = BPF_CORE_READ(f_path.mnt, mnt_sb, s_magic);
  if (s_magic == PROC_SUPER_MAGIC) {
    return NULL;
  }
  // NOLINTNEXTLINE(bugprone-sizeof-expression): it's used inside eBPF macro.
  struct inode *inode = BPF_CORE_READ(f_path.dentry, d_inode);
  if (inode_out) {
    *inode_out = inode;
  }

  unsigned dev_major = imajor(inode);
  // Skip PTY devices
  if (dev_major == UNIX98_PTY_SLAVE_MAJOR)
    return NULL;
  return f_path.dentry;
}

/// Read the path strings from the given fd and store them in the event
/// \return 0 on success, 1 on error
static inline int read_fd_path_strings(int fd, mkcheck2_path_t path) {
  struct dentry *dentry = get_tracing_dentry(fd, NULL);
  if (!dentry)
    return 1;
  return read_dentry_strings(dentry, path);
}

/// Submit the staged event to the ring buffer
/// @return true if the event was submitted, false if the event was ignored
__attribute__((always_inline)) static inline bool __probe_return(struct trace_event_raw_sys_exit *ctx) {
  mkcheck2_debug("probe_return[id=%d]: %d", ctx->id, ctx->ret);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct mkcheck2_staging_event *event = bpf_map_lookup_elem(&staging_events, &pid_tgid);
  if (!event) {
    mkcheck2_debug("probe_return[id=%d]: No event for pid=%d", ctx->id, pid_tgid);
    return false;
  }

  if (ctx->ret < 0) {
    // Ignore the event if the syscall failed
    bpf_map_delete_elem(&staging_events, &pid_tgid);
    mkcheck2_debug("probe_return[id=%d]: Ignoring event for pid=%d", ctx->id, pid_tgid);
    return false;
  }

  // Copy the event to the ring buffer
  void *rb_event = NULL;
  if (event->type_kind == MKCHECK2_STAGING_EVENT_TYPE_EVENT) {
    rb_event = bpf_ringbuf_reserve(&events, sizeof(struct mkcheck2_event), 0);
    if (!rb_event)
      goto buffer_full;
    mkcheck2_event_clone(rb_event, &event->u.event);
  } else if (event->type_kind == MKCHECK2_STAGING_EVENT_TYPE_FAT_EVENT) {
    rb_event = bpf_ringbuf_reserve(&events, sizeof(struct mkcheck2_fat_event), 0);
    if (!rb_event)
      goto buffer_full;
    mkcheck2_fat_event_clone(rb_event, &event->u.fat_event);
  } else if (event->type_kind == MKCHECK2_STAGING_EVENT_TYPE_FAT2_EVENT) {
    rb_event = bpf_ringbuf_reserve(&events, sizeof(struct mkcheck2_fat2_event), 0);
    if (!rb_event)
      goto buffer_full;
    mkcheck2_fat2_event_clone(rb_event, &event->u.fat2_event);
  } else {
    mkcheck2_debug("probe_return[id=%d]: Unknown event type for pid=%d", ctx->id, pid_tgid);
    return false;
  }

  // Submit the event
  bpf_ringbuf_submit(rb_event, 0);
  bpf_map_delete_elem(&staging_events, &pid_tgid);
  mkcheck2_debug("probe_return[id=%d]: Submitted event for pid=%d", ctx->id, pid_tgid);
  return true;
buffer_full:
  report_fatal_error(kErrorRingBufferFull);
  mkcheck2_debug("probe_return[id=%d]: Ring buffer full", ctx->id);
  return false;
}
static inline int probe_return(struct trace_event_raw_sys_exit *ctx) {
  __probe_return(ctx);
  return 0;
}

#define __TRACE_SYSCALL_ENTER_EXIT_EVENT(name, probe)                                                                  \
  SEC("tracepoint/syscalls/sys_exit_" #name)                                                                           \
  int tracepoint__syscalls__sys_exit_##name(struct trace_event_raw_sys_exit *ctx) { return probe(ctx); }               \
  static inline int __tracepoint__syscalls__sys_enter_##name(struct trace_event_raw_sys_enter *ctx);                   \
  SEC("tracepoint/syscalls/sys_enter_" #name)                                                                          \
  int tracepoint__syscalls__sys_enter_##name(struct trace_event_raw_sys_enter *ctx) {                                  \
    mkcheck2_debug("probe_enter[id=%d]: %d pid=%d", ctx->id, ctx->args[0], bpf_get_current_pid_tgid() >> 32);          \
    return __tracepoint__syscalls__sys_enter_##name(ctx);                                                              \
  }                                                                                                                    \
  static inline int __tracepoint__syscalls__sys_enter_##name(struct trace_event_raw_sys_enter *ctx)
#define TRACE_SYSCALL_ENTER_EXIT_EVENT(name) __TRACE_SYSCALL_ENTER_EXIT_EVENT(name, probe_return)

TRACE_SYSCALL_ENTER_EXIT_EVENT(execve) {
  struct mkcheck2_event *event = NULL;
  struct task_struct *task;
  pid_t pid;
  struct tracing_process_info pinfo;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid = pid_tgid >> 32;
  task = (struct task_struct *)bpf_get_current_task();
  pid_t ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);

  if (bpf_map_lookup_elem(&tracing_pinfo, &ppid) == NULL && pid != root_ppid)
    return 0;

  mkcheck2_debug("execve[%d] ppid=%d", bpf_get_current_pid_tgid(), ppid);

  // Insert the pid to the tracing_pids map
  tracing_process_info_init(&pinfo, ppid, get_and_inc_next_uid());
  bpf_map_update_elem(&tracing_pinfo, &pid, &pinfo, BPF_ANY);

  // Create an event and fill it
  event = staging_event_allocate(pid_tgid);
  if (!event) {
    report_fatal_error(kErrorRingBufferFull);
    return 0;
  }
  if (bpf_core_read_user_str(event->path, sizeof(event->path), (const char *)ctx->args[0]) < 0)
    goto err;

  init_event_header(pid, pinfo.uid, kEventTypeExec, &event->header);
  event->payload = ppid;

  return 0;

err:
  staging_event_deallocate(pid_tgid);
  report_fatal_error(kErrorReadUserStr);
  return 0;
}

__attribute__((always_inline)) static void __execveat_at_fdcwd(struct trace_event_raw_sys_enter *ctx,
                                                               struct tracing_process_info pinfo, u64 pid_tgid,
                                                               pid_t pid, pid_t ppid) {
  struct mkcheck2_event *event = NULL;
  // Create an event and fill it
  event = staging_event_allocate(pid_tgid);
  if (!event) {
    return;
  }
  if (bpf_core_read_user_str(event->path, sizeof(event->path), (const char *)ctx->args[1]) < 0)
    goto err;

  init_event_header(pid, pinfo.uid, kEventTypeExec, &event->header);
  event->payload = ppid;
  return;
err:
  staging_event_deallocate(pid_tgid);
  report_fatal_error(kErrorReadUserStr);
}

TRACE_SYSCALL_ENTER_EXIT_EVENT(execveat) {
  struct task_struct *task;
  pid_t pid;
  struct tracing_process_info pinfo;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid = pid_tgid >> 32;
  task = (struct task_struct *)bpf_get_current_task();
  pid_t ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);

  if (bpf_map_lookup_elem(&tracing_pinfo, &ppid) == NULL && pid != root_ppid)
    return 0;

  // Insert the pid to the tracing_pids map
  tracing_process_info_init(&pinfo, ppid, get_and_inc_next_uid());
  bpf_map_update_elem(&tracing_pinfo, &pid, &pinfo, BPF_ANY);

  int dfd = ctx->args[0];
  const char *path = (const char *)ctx->args[1];

  if (dfd == AT_FDCWD) { // fast-path: no need to allocate buffer for base dirname
    __execveat_at_fdcwd(ctx, pinfo, pid_tgid, pid, ppid);
    return 0;
  }

  const struct inode *inode = NULL;
  struct dentry *dentry = get_tracing_dentry(dfd, &inode);
  if (!dentry)
    return 0;

  struct mkcheck2_fat_event *event = NULL;
  event = staging_fat_event_allocate(pid_tgid);
  if (!event) {
    report_fatal_error(kErrorRingBufferFull);
    return 0;
  }

  if (read_dentry_strings(dentry, event->path[0]) != 0) {
    staging_event_deallocate(pid_tgid);
    goto err;
  }

  if (bpf_core_read_user_str(event->path[1], sizeof(event->path[1]), path) < 0) {
    staging_event_deallocate(pid_tgid);
    goto err;
  }

  init_event_header(pid, pinfo.uid, kEventTypeExecAt, &event->header);
  mkcheck2_debug("execveat[pid=%d] ppid=%d, path=%s", pid, ppid, path);
  event->payload = ppid;

  return 0;
err:
  staging_event_deallocate(pid_tgid);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int tracepoint__syscalls__sys_exit_clone3(struct trace_event_raw_sys_exit *ctx) {
  // NOTE: We trace only the exit event of the clone3 syscall raised by the child process.
  // This is because the subsequent events like execve raised by the child process might
  // be handled **before** the exit event of the clone3 syscall of the parent process.
  pid_t ret = ctx->ret;
  if (ret < 0 || ret != 0) {
    mkcheck2_debug("clone3[%d] skipped: ret=%d", pid, ret);
    // Ignore the event came from the parent process (ret != 0) or the clone failed (ret < 0)
    return 0;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  // PID in userland's view, that can be same across threads
  pid_t pid = pid_tgid >> 32;
  // Unique thread ID in userland's view
  pid_t tid = pid_tgid & 0xFFFFFFFF;

  if (pid != tid) {
    // When pid != tid, it means the child process is created with CLONE_THREAD flag.
    // As we uniformly trace all the threads as a single process, we just ignore the child
    // thread creation.
    return 0;
  }

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  // PID of the parent process in userland's view
  pid_t ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);

  mkcheck2_debug("clone3[%d] ppid=%d, tid=%d", pid, ppid, tid);
  mkcheck2_debug("clone3[%d] pid_tgid=%ld", pid, pid_tgid);

  if (bpf_map_lookup_elem(&tracing_pinfo, &ppid) == NULL && ppid != root_ppid)
    return 0;

  struct tracing_process_info pinfo;
  // Insert the pid to the tracing_pids map
  tracing_process_info_init(&pinfo, ppid, get_and_inc_next_uid());
  bpf_map_update_elem(&tracing_pinfo, &pid, &pinfo, BPF_ANY);

  // Create an event and fill it
  struct mkcheck2_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    report_fatal_error(kErrorRingBufferFull);
    return 0;
  }

  init_event_header(pid, pinfo.uid, kEventTypeClone, &event->header);
  event->payload = ppid;

  bpf_ringbuf_submit(event, 0);

  return 0;
}

TRACE_SYSCALL_ENTER_EXIT_EVENT(chdir) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = pid_tgid >> 32;
  u64 uid;
  if (!is_tracing_pid(pid, &uid))
    return 0;

  const void *path = (const void *)ctx->args[0];
  struct mkcheck2_event *event = NULL;

  event = staging_event_allocate(pid_tgid);
  if (!event) {
    report_fatal_error(kErrorRingBufferFull);
    return 0;
  }
  if (bpf_core_read_user_str(event->path, sizeof(event->path), path) < 0)
    goto err;

  init_event_header(pid, uid, kEventTypeChdir, &event->header);
  return 0;
err:
  staging_event_deallocate(pid_tgid);
  report_fatal_error(kErrorReadUserStr);
  return 0;
}

__attribute__((always_inline)) static inline void __submit_fd_event_with_dentry(struct tracing_process_info *pinfo,
                                                                                u64 pid_tgid, struct dentry *dentry,
                                                                                const struct inode *inode, int type,
                                                                                int line) {
  u32 ino = BPF_CORE_READ(inode, i_ino);
  if (!tracing_process_info_insert_fingerprint(pinfo, ino, type)) {
    // The fingerprint is already present
    return;
  }
  pid_t pid = pid_tgid >> 32;
  // Update the process info
  bpf_map_update_elem(&tracing_pinfo, &pid, pinfo, BPF_ANY);

  struct mkcheck2_event *event = __staging_event_allocate(pid_tgid, line);
  if (!event) {
    // __staging_event_allocate() already reported the error
    return;
  }

  __init_event_header(pid, pinfo->uid, type, line, &event->header);

  // If it's fifo, use the inode number as the path
  umode_t mode = BPF_CORE_READ(inode, i_mode);
  if (mode & S_IFIFO) {
    event->payload = ino;
    return;
  }

  if (read_dentry_strings(dentry, event->path) != 0) {
    staging_event_deallocate(pid_tgid);
    __report_fatal_error(kErrorReadDentryStr, line);
    return;
  }

#ifdef DEBUG
  if (type == kEventTypeOutput) {
    bpf_printk("[mkcheck2] Output event: fd=%d, ino=%u", fd, ino);
  }
#endif
}

static inline void __submit_fd_event_without_pid_check(struct tracing_process_info *pinfo, u64 pid_tgid, int fd,
                                                       int type, int line) {
  const struct inode *inode = NULL;
  struct dentry *dentry = get_tracing_dentry(fd, &inode);
  if (!dentry)
    return;
  return __submit_fd_event_with_dentry(pinfo, pid_tgid, dentry, inode, type, line);
}

static inline void __submit_fd_event(int fd, int type, int line) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = pid_tgid >> 32;

  // Check if the pid is in the tracing_pids map
  struct tracing_process_info *pinfo = bpf_map_lookup_elem(&tracing_pinfo, &pid);
  if (!pinfo)
    return;
  return __submit_fd_event_without_pid_check(pinfo, pid_tgid, fd, type, line);
}

#define submit_fd_event(fd, type) __submit_fd_event(fd, type, __LINE__)

TRACE_SYSCALL_ENTER_EXIT_EVENT(fchdir) {
  submit_fd_event(ctx->args[0], kEventTypeChdir);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(read) {
  submit_fd_event(ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(readv) {
  submit_fd_event(ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(pread64) {
  submit_fd_event(ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(preadv) {
  submit_fd_event(ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(write) {
  submit_fd_event(ctx->args[0], kEventTypeOutput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(writev) {
  submit_fd_event(ctx->args[0], kEventTypeOutput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(pwrite64) {
  submit_fd_event(ctx->args[0], kEventTypeOutput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(pwritev) {
  submit_fd_event(ctx->args[0], kEventTypeOutput);
  return 0;
}

static inline void __submit_path_event_without_pid_check(u64 pid_tgid, u64 uid, const void *path,
                                                         enum mkcheck2_event_type type, int line) {
  pid_t pid = pid_tgid >> 32;
  struct mkcheck2_event *event = NULL;
  event = staging_event_allocate(pid_tgid);
  if (!event) {
    __report_fatal_error(kErrorRingBufferFull, line);
    return;
  }
  if (bpf_core_read_user_str(event->path, sizeof(event->path), path) < 0)
    goto err;

  __init_event_header(pid, uid, type, line, &event->header);
  return;
err:
  staging_event_deallocate(pid_tgid);
  __report_fatal_error(kErrorReadUserStr, line);
}
static inline void __submit_path_event(const void *path, enum mkcheck2_event_type type, int line) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = pid_tgid >> 32;
  u64 uid;
  if (!is_tracing_pid(pid, &uid))
    return;
  return __submit_path_event_without_pid_check(pid_tgid, uid, path, type, line);
}

#define submit_path_event(path, type) __submit_path_event(path, type, __LINE__)

static inline bool is_empty_string(const void *str) {
  char c;
  if (bpf_core_read_user(&c, sizeof(c), str) < 0)
    return true;
  return c == '\0';
}

static void __submit_path_at_event_without_pid_check(struct tracing_process_info *pinfo, u64 pid_tgid, int dfd,
                                                     const void *path, int type, int line) {
  if (dfd == AT_FDCWD) { // fast-path: no need to allocate buffer for base dirname
    __submit_path_event_without_pid_check(pid_tgid, pinfo->uid, path, kEventTypeInput,
                                          line); // TODO: type can be Output or other
    return;
  }

  const struct inode *inode = NULL;
  struct dentry *dentry = get_tracing_dentry(dfd, &inode);
  if (!dentry)
    return;

  if (is_empty_string(path)) { // fast-path: empty path is the same as dfd
    return __submit_fd_event_with_dentry(pinfo, pid_tgid, dentry, inode, kEventTypeInput,
                                         line); // TODO: type can be Output or other
  }

  struct mkcheck2_fat_event *event = NULL;
  event = __staging_fat_event_allocate(pid_tgid, line);
  if (!event) {
    __report_fatal_error(kErrorRingBufferFull, line);
    return;
  }

  if (read_dentry_strings(dentry, event->path[0]) != 0) {
    __report_fatal_error(kErrorReadDentryStr, line);
    goto err;
  }

  if (bpf_core_read_user_str(event->path[1], sizeof(event->path[1]), path) < 0) {
    __report_fatal_error(kErrorReadUserStr, line);
    goto err;
  }

  pid_t pid = pid_tgid >> 32;
  __init_event_header(pid, pinfo->uid, type, line, &event->header);
  return;
err:
  staging_event_deallocate(pid_tgid);
}

static void __submit_path_at_event(struct trace_event_raw_sys_enter *ctx, int dfd, const void *path, int type,
                                   int line) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = pid_tgid >> 32;
  mkcheck2_debug("submit_path_at_event[id=%d]: pid=%d, path=%s", ctx->id, pid, (const char *)path);

  struct tracing_process_info *pinfo = bpf_map_lookup_elem(&tracing_pinfo, &pid);
  if (!pinfo)
    return;

  __submit_path_at_event_without_pid_check(pinfo, pid_tgid, dfd, path, type, line);
}

#define submit_path_at_event(dfd, path, type) __submit_path_at_event(ctx, dfd, path, type, __LINE__)

static inline void __submit_fat_path_event_without_pid_check(u64 pid_tgid, u64 uid, const void *path1,
                                                             const void *path2, enum mkcheck2_event_type type,
                                                             int line) {
  struct mkcheck2_fat_event *event = NULL;
  pid_t pid = pid_tgid >> 32;
  event = __staging_fat_event_allocate(pid_tgid, line);
  if (!event) {
    __report_fatal_error(kErrorRingBufferFull, line);
    return;
  }
  if (bpf_core_read_user_str(event->path[0], sizeof(event->path[0]), path1) < 0)
    goto err;
  if (bpf_core_read_user_str(event->path[1], sizeof(event->path[1]), path2) < 0)
    goto err;

  __init_event_header(pid, uid, type, line, &event->header);
  return;

err:
  staging_event_deallocate(pid_tgid);
  __report_fatal_error(kErrorReadUserStr, line);
  return;
}
static inline void __submit_fat_path_event(const void *path1, const void *path2, enum mkcheck2_event_type type,
                                           int line) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = pid_tgid >> 32;
  u64 uid;

  if (!is_tracing_pid(pid, &uid))
    return;
  return __submit_fat_path_event_without_pid_check(pid_tgid, uid, path1, path2, type, line);
}

#define submit_fat_path_event(path1, path2, type) __submit_fat_path_event(path1, path2, type, __LINE__)

__attribute__((always_inline)) static inline void __submit_fd2_path2_at_event(struct trace_event_raw_sys_enter *ctx,
                                                                              int dfd1, int dfd2, const void *path1,
                                                                              const void *path2, int type, int line) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = pid_tgid >> 32;
  u64 uid;
  if (!is_tracing_pid(pid, &uid))
    return;

  struct mkcheck2_fat2_event *event = NULL;
  event = staging_fat2_event_allocate(pid_tgid);
  if (!event) {
    __report_fatal_error(kErrorRingBufferFull, line);
    return;
  }

  if (read_fd_path_strings(dfd1, event->path[0]) != 0) {
    __report_fatal_error(kErrorReadDentryStr, line);
    goto err;
  }
  if (read_fd_path_strings(dfd2, event->path[1]) != 0) {
    __report_fatal_error(kErrorReadDentryStr, line);
    goto err;
  }

  if (bpf_core_read_user_str(event->path[2], sizeof(event->path[2]), path1) < 0) {
    __report_fatal_error(kErrorReadUserStr, line);
    goto err;
  }
  if (bpf_core_read_user_str(event->path[3], sizeof(event->path[3]), path2) < 0) {
    __report_fatal_error(kErrorReadUserStr, line);
    goto err;
  }

  __init_event_header(pid, uid, type, line, &event->header);
  return;
err:
  staging_event_deallocate(pid_tgid);
}

#define submit_fd2_path2_at_event(dfd1, dfd2, path1, path2, type)                                                      \
  __submit_fd2_path2_at_event(ctx, dfd1, dfd2, path1, path2, type, __LINE__)

__attribute__((always_inline)) static inline void __submit_fd1_path2_at_event(struct trace_event_raw_sys_enter *ctx,
                                                                              int dfd, const void *path1,
                                                                              const void *path2, int type, int line) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = pid_tgid >> 32;
  u64 uid;
  if (!is_tracing_pid(pid, &uid))
    return;

  struct mkcheck2_fat2_event *event = NULL;
  event = staging_fat2_event_allocate(pid_tgid);
  if (!event) {
    __report_fatal_error(kErrorRingBufferFull, line);
    return;
  }

  if (read_fd_path_strings(dfd, event->path[0]) != 0) {
    __report_fatal_error(kErrorReadDentryStr, line);
    goto err;
  }

  if (bpf_core_read_user_str(event->path[1], sizeof(event->path[2]), path1) < 0) {
    __report_fatal_error(kErrorReadUserStr, line);
    goto err;
  }
  if (bpf_core_read_user_str(event->path[2], sizeof(event->path[3]), path2) < 0) {
    __report_fatal_error(kErrorReadUserStr, line);
    goto err;
  }

  __init_event_header(pid, uid, type, line, &event->header);
  return;
err:
  staging_event_deallocate(pid_tgid);
}

#define submit_fd1_path2_at_event(dfd, path1, path2, type)                                                             \
  __submit_fd1_path2_at_event(ctx, dfd, path1, path2, type, __LINE__)

TRACE_SYSCALL_ENTER_EXIT_EVENT(newstat) {
  submit_path_event((const void *)ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(statx) {
  submit_path_at_event(ctx->args[0], (const void *)ctx->args[1], kEventTypeInputAt);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(newfstat) {
  submit_fd_event(ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(newfstatat) {
  submit_path_at_event(ctx->args[0], (const void *)ctx->args[1], kEventTypeInputAt);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(unlink) {
  submit_path_event((const void *)ctx->args[0], kEventTypeRemove);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(rename) {
  submit_fat_path_event((void *)ctx->args[0], (void *)ctx->args[1], kEventTypeRename);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(mmap) {
  int prot = ctx->args[2];
  int flags = ctx->args[3];
  int fd = ctx->args[4];
  if (fd == -1) {
    return 0;
  }
  enum mkcheck2_event_type type = (flags & MAP_SHARED) && (prot & PROT_WRITE) ? kEventTypeOutput : kEventTypeInput;
  submit_fd_event(fd, type);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(access) {
  const void *path = (const void *)ctx->args[0];
  SKIP_PROC_SELF_EXEC(path);
  submit_path_event(path, kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(ftruncate) {
  submit_fd_event(ctx->args[0], kEventTypeOutput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(getdents) {
  submit_fd_event(ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(mkdir) {
  submit_path_event((const void *)ctx->args[0], kEventTypeOutput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(rmdir) {
  submit_path_event((const void *)ctx->args[0], kEventTypeRemove);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(link) {
  submit_fat_path_event((void *)ctx->args[0], (void *)ctx->args[1], kEventTypeLink);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(symlink) {
  submit_fat_path_event((void *)ctx->args[0], (void *)ctx->args[1], kEventTypeLink);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(readlink) {
  const void *path = (const void *)ctx->args[0];
  SKIP_PROC_SELF_EXEC(path);
  submit_path_event(path, kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(readlinkat) {
  submit_path_at_event(ctx->args[0], (const void *)ctx->args[1], kEventTypeInputAt);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(utime) {
  submit_path_event((const void *)ctx->args[0], kEventTypeOutput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(utimensat) {
  submit_path_at_event(ctx->args[0], (const void *)ctx->args[1], kEventTypeOutputAt);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(fsetxattr) {
  submit_fd_event(ctx->args[0], kEventTypeOutput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(getxattr) {
  submit_fd_event(ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(lgetxattr) {
  submit_fd_event(ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(llistxattr) {
  submit_fd_event(ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(getdents64) {
  submit_fd_event(ctx->args[0], kEventTypeInput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(mkdirat) {
  submit_path_at_event(ctx->args[0], (const void *)ctx->args[1], kEventTypeOutputAt);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(unlinkat) {
  submit_path_at_event(ctx->args[0], (const void *)ctx->args[1], kEventTypeRemoveAt);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(faccessat) {
  submit_path_at_event(ctx->args[0], (const void *)ctx->args[1], kEventTypeInputAt);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(faccessat2) {
  submit_path_at_event(ctx->args[0], (const void *)ctx->args[1], kEventTypeInputAt);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(fallocate) {
  submit_fd_event(ctx->args[0], kEventTypeOutput);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(linkat) {
  submit_fd2_path2_at_event(ctx->args[0], ctx->args[2], (const void *)ctx->args[1], (const void *)ctx->args[3],
                            kEventTypeLinkAt);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(renameat) {
  submit_fd2_path2_at_event(ctx->args[0], ctx->args[2], (const void *)ctx->args[1], (const void *)ctx->args[3],
                            kEventTypeRenameAt);
  return 0;
}
TRACE_SYSCALL_ENTER_EXIT_EVENT(symlinkat) {
  int dfd = ctx->args[1];
  if (dfd == AT_FDCWD) {
    submit_fat_path_event((const void *)ctx->args[0], (const void *)ctx->args[2], kEventTypeSymlink);
    return 0;
  }
  submit_fd1_path2_at_event(dfd, (const void *)ctx->args[0], (const void *)ctx->args[2], kEventTypeSymlinkAt);
  return 0;
}
SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
  pid_t pid;
  struct mkcheck2_event *event = NULL;
  struct task_struct *task;

  pid = bpf_get_current_pid_tgid() >> 32;
  u64 uid;

  // Check if the pid is in the tracing_pids map
  if (!is_tracing_pid(pid, &uid))
    return 0;

  task = (struct task_struct *)bpf_get_current_task();

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    report_fatal_error(kErrorRingBufferFull);
    return 0;
  }

  init_event_header(pid, uid, kEventTypeExit, &event->header);
  event->payload = BPF_CORE_READ(task, exit_code) >> 8;
  event->path[0][0] = '\0';

  bpf_ringbuf_submit(event, 0);

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
