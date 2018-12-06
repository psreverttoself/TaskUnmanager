#include "Unmanager.h"
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(*_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, void*, unsigned long, unsigned long*);

int Unmanager::InjectDLL(int pid, const char* path)
{
	int result = 0;
	HANDLE remoteProcessHandle;
	HANDLE remoteThreadHandle;
	
	remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

	if (remoteProcessHandle)
	{
		void* remoteAddress = VirtualAllocEx(remoteProcessHandle, 0, lstrlenA(path), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (remoteAddress)
		{
			if (WriteProcessMemory(remoteProcessHandle, remoteAddress, path, lstrlenA(path), NULL))
			{
				void* kernel32Address = LoadLibraryA("kernel32.dll");

				if (kernel32Address)
				{
					void* loadLibraryAddress = GetProcAddress((HMODULE) kernel32Address, "LoadLibraryA");

					if (loadLibraryAddress)
					{
						remoteThreadHandle = CreateRemoteThread(remoteProcessHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, remoteAddress, NULL, NULL);

						if (remoteThreadHandle)
						{
							result = 1;
						}
					}
				}
			}

			int lastError = GetLastError();

			VirtualFreeEx(remoteProcessHandle, remoteAddress, lstrlenA(path), MEM_RELEASE);
		}
	}

	CloseHandle(remoteProcessHandle);
	CloseHandle(remoteThreadHandle);

	return result;
}

int Unmanager::GetPidFromProcessName(const wchar_t* name)
{
	char* buff;

	SYSTEM_PROCESS_INFORMATION procInfo;

	HMODULE ntdllHandle = LoadLibraryA("ntdll.dll");

	_NtQuerySystemInformation MyNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdllHandle, "NtQuerySystemInformation");

	unsigned long size;
		int error;

	NTSTATUS status = MyNtQuerySystemInformation(SystemProcessInformation, buff, 0, &size);

	if (NT_ERROR(status))
	{
		buff = (char*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);

		status = MyNtQuerySystemInformation(SystemProcessInformation, buff, size, &size);

		if (NT_SUCCESS(status))
		{
			int offset = 0;
			
			while (1)
			{
				procInfo = *((SYSTEM_PROCESS_INFORMATION*)(buff + offset));

				if (lstrcmpiW(procInfo.ImageName.Buffer, name) == 0)
				{
					int pid = (int)procInfo.UniqueProcessId;

					return pid;
				}

				if (procInfo.NextEntryOffset == 0) break;

				offset += procInfo.NextEntryOffset;
			}
		}


		HeapFree(GetProcessHeap(), 0, (LPVOID) buff);

		error = GetLastError();
	}

	return -1;
}