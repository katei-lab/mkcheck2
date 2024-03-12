## How eBPF contributes to the tracing performance

- Can filter out unnecessary events before they reach the user space
  - Uninteresting syscalls (e.g. `getpid`, `flock`)
  - Events that are not needed for the current analysis
  - Duplicate events (e.g. `read` against the same file descriptor in a loop)

## How eBPF contributes to the simplicity of the tracing implementation

- Don't need to track file descriptors issued by syscalls
  - Kernel does it for us, so we can just reference them without maintaining a duplicate map
    by ourselves.
