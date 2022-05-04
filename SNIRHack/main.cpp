#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#include <windows.h>

// list all PIDs and TIDs
#include <tlhelp32.h>
#include <Psapi.h>

#include "ntinfo.h"

std::vector<DWORD> threadList(DWORD pid);
DWORD GetThreadStartAddress(HANDLE processHandle, HANDLE hThread);
DWORD FindProcessId(DWORD &pId);

int main() {
	DWORD dwProcID;

	if (!FindProcessId(dwProcID)) {
		std::cerr << "Process ID couldn\'t be found." << std::endl;
		return EXIT_FAILURE;
	}

	HANDLE hProcHandle = NULL;

	printf("PID %d (0x%x)\n", dwProcID, dwProcID);
	std::cout << "Grabbing handle" << std::endl;
	hProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcID);

	if (hProcHandle == INVALID_HANDLE_VALUE || hProcHandle == NULL) {
		std::cerr << "Failed to open process -- invalid handle" << std::endl;
		std::cerr << "Error code: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	else {
		std::cout << "Success" << std::endl;
	}

	std::vector<DWORD> threadId = threadList(dwProcID);
	int stackNum = 0;
	for (auto it = threadId.begin(); it != threadId.end(); ++it) {
		HANDLE threadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, *it);
		DWORD threadStartAddress = GetThreadStartAddress(hProcHandle, threadHandle);
		printf("TID: 0x%04x = THREADSTACK%2d BASE ADDRESS: 0x%04x\n", *it, stackNum, threadStartAddress);
		stackNum++;
	}

	return EXIT_SUCCESS;
}

std::vector<DWORD> threadList(DWORD pid) {
	std::vector<DWORD> vect = std::vector<DWORD>();
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h == INVALID_HANDLE_VALUE)
		return vect;

	THREADENTRY32 te;
	te.dwSize = sizeof(te);
	if (Thread32First(h, &te)) {
		do {
			if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
				sizeof(te.th32OwnerProcessID)) {


				if (te.th32OwnerProcessID == pid) {
					printf("PID: %04d Thread ID: 0x%04x\n", te.th32OwnerProcessID, te.th32ThreadID);
					vect.push_back(te.th32ThreadID);
				}

			}
			te.dwSize = sizeof(te);
		} while (Thread32Next(h, &te));
	}

	return vect;
}

DWORD GetThreadStartAddress(HANDLE processHandle, HANDLE hThread) {
	DWORD used = 0, ret = 0;
	DWORD stacktop = 0, result = 0;

	MODULEINFO mi;

	GetModuleInformation(processHandle, GetModuleHandle("kernel32.dll"), &mi, sizeof(mi));
	stacktop = (DWORD)GetThreadStackTopAddress_x86(processHandle, hThread);

	CloseHandle(hThread);

	if (stacktop) {

		DWORD* buf32 = new DWORD[4096];

		if (ReadProcessMemory(processHandle, (LPCVOID)(stacktop - 4096), buf32, 4096, NULL)) {
			for (int i = 4096 / 4 - 1; i >= 0; --i) {
				if (buf32[i] >= (DWORD)mi.lpBaseOfDll && buf32[i] <= (DWORD)mi.lpBaseOfDll + mi.SizeOfImage) {
					result = stacktop - 4096 + i * 4;
					break;
				}

			}
		}

		delete buf32;
	}

	return result;
}

DWORD FindProcessId(DWORD& pId)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_stricmp(entry.szExeFile, "Projet_SNIR.exe") == 0)
			{
				pId = entry.th32ProcessID;
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);

	return 0;
}