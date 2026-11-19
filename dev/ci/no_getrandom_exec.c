// 用 seccomp 把 getrandom(2) 变成 ENOSYS，然后 exec 目标命令。
//
// 用途：CI 门禁。老内核（< 3.17，例如 CentOS 6 的 2.6.32、CentOS 7 的 3.10）根本没有这个
// 系统调用，而 musl 的 getentropy() 不会回退 /dev/urandom —— aws-lc 在那种机器上会
// `getentropy failed.` + abort。CI runner 的内核都是新的，直接跑制品**永远复现不出来**，
// 所以这里用 seccomp 在任意 runner 上把那条路径逼出来。
//
// 只依赖内核头文件，不依赖 libseccomp：门禁本身不该再引入一个构建依赖。
// 没装内核 UAPI 头的机器上 `__NR_getrandom` 可能没定义（CentOS 6 就是），所以给了兜底值。

#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if defined(__x86_64__)
#define GATE_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define GATE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "请为这个架构补 GATE_AUDIT_ARCH 与 __NR_getrandom 的兜底值"
#endif

#ifndef __NR_getrandom
#if defined(__x86_64__)
#define __NR_getrandom 318
#elif defined(__aarch64__)
#define __NR_getrandom 278
#endif
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
    return 2;
  }

  struct sock_filter filter[] = {
      // 只对本机架构生效：别的 ABI 直接杀掉，避免规则被绕过。
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, GATE_AUDIT_ARCH, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      // getrandom() -> ENOSYS（= 内核 < 3.17 的行为），其它系统调用放行。
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getrandom, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    fprintf(stderr, "no-getrandom: PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
    return 2;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
    fprintf(stderr, "no-getrandom: PR_SET_SECCOMP: %s\n", strerror(errno));
    return 2;
  }

  fprintf(stderr,
          "[no-getrandom] getrandom() 现在返回 ENOSYS（模拟 kernel < 3.17，"
          "例如 CentOS 6 的 2.6.32）\n");
  fflush(stderr);

  execvp(argv[1], &argv[1]);
  fprintf(stderr, "no-getrandom: exec %s: %s\n", argv[1], strerror(errno));
  return 127;
}
