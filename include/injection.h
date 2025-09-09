#pragma once
#include <windows.h>
#include <stdio.h>

#define okay(MSG, ...) printf("[+] "          MSG "\n", ##__VA_ARGS__)
#define info(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define warn(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define print_error(FUNCTION_NAME)                                   \
    do {                                                             \
        fprintf(stderr,                                              \
                "[!] [" FUNCTION_NAME "] falhou, erro: 0x%lx\n"     \
                "[*] %s:%d\n", GetLastError(), __FILE__, __LINE__);  \
    } while (0)


BOOL ShellcodeInjection(
    _In_ CONST DWORD PID,
    _In_ CONST PBYTE Payload,
    _In_ CONST SIZE_T PayloadSize
);

