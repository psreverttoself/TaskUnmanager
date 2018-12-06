#include "FunctionHooker.h"
#include <Windows.h>

int FunctionHooker::HookFunction32(void* hookedFunctionAddress, void* replacementFunctionAddress, HookStruct32* hook)
{
	if (hook->Valid)
	{
		return 0;
	}

	int replacementAddress = (int)replacementFunctionAddress;
	int offset = 0;
	unsigned char lastByte = 0;
	SIZE_T numWritten = 0;

	if (!ReadProcessMemory(GetCurrentProcess(), hookedFunctionAddress, hook->OriginalBytes, 6, NULL))
	{
		return 0;
	}

	hook->OriginalFunction = VirtualAlloc(0, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!hook->OriginalFunction)
	{
		return 0;
	}

	if (!RtlSecureZeroMemory(hook->OriginalFunction, 1024))
	{
		return 0;
	}

	hook->ReplacementBytes[0] = 0x68; // push
	hook->ReplacementBytes[5] = 0xc3; // retn

	if (!WriteProcessMemory(GetCurrentProcess(), hook->ReplacementBytes + 1, &replacementAddress, 4, NULL))
	{
		return 0;
	}


	do
	{
		if (!WriteProcessMemory(GetCurrentProcess(), ((char*)hook->OriginalFunction) + offset, ((char*)hookedFunctionAddress) + offset, 1, &numWritten))
		{
			return 0;
		}

		if (offset > 0)
		{
			lastByte = *(((char*)hook->OriginalFunction) + offset - 1);

			if (lastByte == 0xc2)
			{
				break;
			}
		}

		lastByte = *(((char*)hook->OriginalFunction) + offset);

		if (lastByte == 0xc3)
		{
			break;
		}

		offset += numWritten;

		if (offset > 1024)
		{
			return 0;
		}
	} while (1);


	if (!WriteProcessMemory(GetCurrentProcess(), hookedFunctionAddress, hook->ReplacementBytes, 6, NULL))
	{
		return 0;
	}

	hook->OriginalFunctionAddress = hookedFunctionAddress;
	hook->Valid = 1;

	return 1;
}

int FunctionHooker::HookFunction64(void* hookedFunctionAddress, void* replacementFunctionAddress, HookStruct64* hook)
{
	if (hook->Valid)
	{
		return 0;
	}

	long long replacementAddress = (long long)replacementFunctionAddress;
	int offset = 0;
	unsigned char lastByte = 0;
	SIZE_T numWritten = 0;

	if (!ReadProcessMemory(GetCurrentProcess(), hookedFunctionAddress, hook->OriginalBytes, 12, NULL))
	{
		return 0;
	}

	hook->OriginalFunction = VirtualAlloc(0, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!hook->OriginalFunction)
	{
		return 0;
	}

	if (!RtlSecureZeroMemory(hook->OriginalFunction, 1024))
	{
		return 0;
	}

	hook->ReplacementBytes[0] = 0x48; // using 64 bit operand
	hook->ReplacementBytes[1] = 0xb8; // mov rax
	hook->ReplacementBytes[10] = 0x50; // push rax
	hook->ReplacementBytes[11] = 0xc3; // retn

	if (!WriteProcessMemory(GetCurrentProcess(), hook->ReplacementBytes + 2, &replacementAddress, 8, NULL))
	{
		return 0;
	}

	do
	{
		if (!WriteProcessMemory(GetCurrentProcess(), ((char*)hook->OriginalFunction) + offset, ((char*)hookedFunctionAddress) + offset, 1, &numWritten))
		{
			return 0;
		}

		if (offset > 0)
		{
			lastByte = *(((char*)hook->OriginalFunction) + offset - 1);

			if (lastByte == 0xc2)
			{
				break;
			}
		}

		lastByte = *(((char*)hook->OriginalFunction) + offset);

		if (lastByte == 0xc3)
		{
			break;
		}

		offset += numWritten;

		if (offset > 1024)
		{
			return 0;
		}

	} while (1);



	if (!WriteProcessMemory(GetCurrentProcess(), hookedFunctionAddress, hook->ReplacementBytes, 12, NULL))
	{
		return 0;
	}

	hook->OriginalFunctionAddress = hookedFunctionAddress;
	hook->Valid = 1;

	return 1;
}

int FunctionHooker::UnhookFunction32(HookStruct32* hook)
{
	if (hook->Valid)
	{
		if (WriteProcessMemory(GetCurrentProcess(), hook->OriginalFunctionAddress, hook->OriginalBytes, 6, NULL))
		{
			hook->Valid = 0;

			if (VirtualFree(hook->OriginalFunction, 0, MEM_RELEASE))
			{
				return 1;
			}

			return 0;
		}
	}

	return 0;
}

int FunctionHooker::UnhookFunction64(HookStruct64* hook)
{
	if (hook->Valid)
	{
		if (WriteProcessMemory(GetCurrentProcess(), hook->OriginalFunctionAddress, hook->OriginalBytes, 10, NULL))
		{
			hook->Valid = 0;

			if (VirtualFree(hook->OriginalFunction, 0, MEM_RELEASE))
			{
				return 1;
			}

			return 0;
		}
	}

	return 0;
}