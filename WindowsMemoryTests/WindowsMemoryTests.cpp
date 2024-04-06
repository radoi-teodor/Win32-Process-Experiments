#include <stdio.h>
#include <Windows.h>
#include "win-api-inclusions.h"

PPROCESS_INFORMATION create_process(wchar_t cmd[]) {
    LPSTARTUPINFOW       si;
    PPROCESS_INFORMATION pi;
    BOOL                 success;

    si = new STARTUPINFOW();
    si->cb = sizeof(LPSTARTUPINFOW);

    pi = new PROCESS_INFORMATION();

    success = CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        si,
        pi);

    if (!success) {
        printf("[x] CreateProcess failed.");
        return NULL;
    }

    return pi;
}

PPROCESS_INFORMATION create_spoofed_process(wchar_t cmd[], int pid) {
    const DWORD attributeCount = 1;

    LPSTARTUPINFOEXW si = new STARTUPINFOEXW();
    si->StartupInfo.cb = sizeof(STARTUPINFOEXW);

    SIZE_T lpSize = 0;

    InitializeProcThreadAttributeList(
        NULL,
        attributeCount,
        0,
        &lpSize);

    si->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(lpSize);

    InitializeProcThreadAttributeList(
        si->lpAttributeList,
        attributeCount,
        0,
        &lpSize);

    HANDLE hParent = OpenProcess(
        PROCESS_CREATE_PROCESS,
        FALSE,
        pid);

    UpdateProcThreadAttribute(
        si->lpAttributeList,
        NULL,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent,
        sizeof(HANDLE),
        NULL,
        NULL);

    PPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

    CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &si->StartupInfo, // folosim optiunile din lista updatata
        pi);

    DeleteProcThreadAttributeList(si->lpAttributeList);
    free(si->lpAttributeList);

    return pi;
}

void close_process(PPROCESS_INFORMATION pi) {
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
}

LPVOID create_page_process(HANDLE p_handle = NULL,
    SIZE_T size = 4000) { // 4000 bytes -> one page
    LPVOID ptr = VirtualAllocEx(
        p_handle,
        NULL,
        size,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    if (ptr == NULL) {
        printf("[!] Create Page Failed With Error : %d \n", GetLastError());
    }

    return ptr;
}

struct PROCESSES {
    DWORD process_num;
    DWORD *processes_id;
};

PROCESSES* enumerate_all_processes() {
    // DLL inclusions
    HMODULE hModule = LoadLibraryA("psapi.dll");
    PVOID pEnumProcesses = GetProcAddress(hModule, "EnumProcesses");
    EnumProcessesFunctionPointer EnumProcesses = (EnumProcessesFunctionPointer)pEnumProcesses;

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return NULL;
    }
    wchar_t new_process_name[] = L"notepad.exe\0";

    cProcesses = cbNeeded / sizeof(DWORD);

    PROCESSES* processes = new PROCESSES;
    processes->process_num = cProcesses;
    processes->processes_id = aProcesses;

    return processes;
}

int main()
{

    wchar_t new_process_name[] = L"notepad.exe\0";

    /*
    PPROCESS_INFORMATION pi = create_process(new_process_name);
    printf("process    : %p\n", pi->hProcess);
    LPVOID page = create_page_process(pi->hProcess);
    printf("page    : %p\n", page);
    */

    PROCESSES *processes = enumerate_all_processes();

    //system("pause");
    //close_process(pi);
    //close_process(spi);
}
