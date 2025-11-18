#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include "syscalls.h"

#define SECCOMP_SYSCALL 317
#define PRCTL_SYSCALL SYS_prctl
#define PR_SET_SECCOMP 22

struct sock_filter {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

struct sock_fprog {
    uint16_t len;
    uint16_t pad[3];
    struct sock_filter *filter;
};


const char *get_syscall_name(uint32_t nr) {
    static char buf[32];

    for (int i = 0; i < syscall_table_size; i++) {
        if (syscall_table[i].nr == nr)
            return syscall_table[i].name;
    }

    snprintf(buf, sizeof(buf), "0x%x", nr);
    return buf;
}

void decode_insn(struct sock_filter *f, int line) {
    printf(" %04d: 0x%02x 0x%02x 0x%02x 0x%08x  ", line, f->code, f->jt, f->jf, f->k);
    
    uint8_t cls = f->code & 0x07;
    
    if (cls == 0x00) {
        if (f->code == 0x20) {
            if (f->k == 0) printf("A = sys_number\n");
            else if (f->k == 4) printf("A = arch\n");
            else printf("A = data[%u]\n", f->k);
        } else {
            printf("A = ?\n");
        }
    } else if (cls == 0x05) {
        if (f->code == 0x15)
            printf("if (A != %s) goto %04d\n", get_syscall_name(f->k), line + f->jf + 1);
        else if (f->code == 0x25)
            printf("if (A > %u) goto %04d\n", f->k, line + f->jf + 1);
        else if (f->code == 0x35)
            printf("if (A >= %u) goto %04d\n", f->k, line + f->jf + 1);
        else if (f->code == 0x05)
            printf("goto %04d\n", line + f->k + 1);
        else
            printf("jmp?\n");
    } else if (cls == 0x06) {
        if (f->k == 0x00000000) printf("return KILL\n");
        else if (f->k == 0x7fff0000) printf("return ALLOW\n");
        else if ((f->k & 0xffff0000) == 0x00050000) printf("return ERRNO(%u)\n", f->k & 0xffff);
        else if (f->k == 0x00030000) printf("return TRAP\n");
        else printf("return 0x%08x\n", f->k);
    } else {
        printf("unknown\n");
    }
}

int read_data(pid_t pid, unsigned long addr, void *buf, size_t len) {
    for (size_t i = 0; i < len; i += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (errno) return -1;
        size_t to_copy = (len - i < sizeof(long)) ? len - i : sizeof(long);
        memcpy((char*)buf + i, &word, to_copy);
    }
    return 0;
}

void dump_filter(pid_t pid, unsigned long prog_addr) {
    struct sock_fprog fprog;
    if (read_data(pid, prog_addr, &fprog, sizeof(fprog)) < 0) {
        fprintf(stderr, "Failed to read sock_fprog\n");
        return;
    }
    
    printf("# Filter length: %u\n", fprog.len);
    printf("# Filter pointer: %p\n", fprog.filter);
    printf(" line  CODE  JT   JF      K\n");
    printf("=================================\n");
    
    for (int i = 0; i < fprog.len; i++) {
        struct sock_filter f;
        if (read_data(pid, (unsigned long)(fprog.filter + i), &f, sizeof(f)) < 0) {
            fprintf(stderr, "Failed to read filter[%d]\n", i);
            break;
        }
        decode_insn(&f, i);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
        return 1;
    }
    
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
        perror("execl");
        exit(1);
    }
    
    int status, found = 0;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    
    while (1) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
        if (!WIFSTOPPED(status)) continue;
        
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        
        long syscall = regs.orig_rax;
        
        if (syscall == SECCOMP_SYSCALL) {
            printf("# Intercepted seccomp()\n");
            dump_filter(pid, regs.rdx);
            found = 1;
            break;
        } else if (syscall == PRCTL_SYSCALL && regs.rdi == PR_SET_SECCOMP && regs.rsi == 2) {
            printf("# Intercepted prctl(PR_SET_SECCOMP)\n");
            dump_filter(pid, regs.rdx);
            found = 1;
            break;
        }
    }
    
    if (found) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    } else {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        fprintf(stderr, "# No seccomp filter found\n");
    }
    
    return found ? 0 : 1;
}
