#include <iostream>
#include <winternl.h>
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>

typedef LONG NTSTATUS;
typedef DWORD KPRIORITY;
typedef WORD UWORD;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

enum THREADINFOCLASS
{
    ThreadBasicInformation,
};

void* GetThreadStackTopAddress(HANDLE hProcess, HANDLE hThread)
{
    bool loadedManually = false;
    HMODULE module = GetModuleHandle(L"ntdll.dll");

    if (!module)
    {
        module = LoadLibrary(L"ntdll.dll");
        loadedManually = true;
    }

    NTSTATUS(__stdcall * NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
    NtQueryInformationThread = reinterpret_cast<decltype(NtQueryInformationThread)>(GetProcAddress(module, "NtQueryInformationThread"));

    if (NtQueryInformationThread)
    {
        NT_TIB tib = { 0 };
        THREAD_BASIC_INFORMATION tbi = { 0 };

        NTSTATUS status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
        if (status >= 0)
        {
            ReadProcessMemory(hProcess, tbi.TebBaseAddress, &tib, sizeof(tbi), nullptr);

            if (loadedManually)
            {
                FreeLibrary(module);
            }
            return tib.StackBase;
        }
    }


    if (loadedManually)
    {
        FreeLibrary(module);
    }

    return nullptr;
}

DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}
int main()
{
    DWORD ProcId = FindProcessId(L"Projet_SNIR.exe");
    if (!ProcId) {
        std::cerr << "[-] Process ID can\'t be found." << std::endl;
        exit(-1);
    }

    std::cout << "[+] Target process ID : " << std::hex << ProcId << std::endl;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, ProcId);

    if (!hProcess) {
        std::cerr << "[-] Error obtaining game handle." << std::endl;
        exit(-1);
    }

    std::cout << "[+] Target Handle Opened : " << std::hex << hProcess << std::endl;

    return 0;
}