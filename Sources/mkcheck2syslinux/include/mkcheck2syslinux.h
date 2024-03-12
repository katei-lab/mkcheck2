#pragma once

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE // for execveat
#endif

#include <unistd.h>

#include <sys/wait.h>

static inline int swift_WSTOPSIG(int status) { return WSTOPSIG(status); }
static inline int swift_WIFEXITED(int status) { return WIFEXITED(status); }
static inline int swift_WEXITSTATUS(int status) { return WEXITSTATUS(status); }
