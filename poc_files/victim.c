#include "common.h"

int main(int argc, char *argv[])
{

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("running victim %s\n", argv[1]);

    //only call safe_function
    codePtr = safe_function;
    char secret[20];
    char *sharedmem = open_shared_mem();
    unsigned idx = string_to_unsigned(argv[1]);

    //call for prctl to protect this process
    protect_me();

    //only then load the secret into memory
    load_secret(secret);

    //mitigation with seccomp also fails
    //protect_me2();

    for (int i = 0; i < 100; i++)
    {
        flush((char *)&codePtr);
        //this arguments are never used on safe_function, but they match the signature of spectre_gadget, that should never be called
        //Since prctl is called, it shouldn't be possible for an attacker to poison the BTB and leak the secret
        spec(&sharedmem[2000], secret, idx);
    }
}