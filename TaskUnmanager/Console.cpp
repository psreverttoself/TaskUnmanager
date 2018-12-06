#include "Console.h"
#include <Windows.h>

int Console::Write(const char* message)
{
	HANDLE stdOut = GetStdHandle(STD_OUTPUT_HANDLE);

	if (stdOut == NULL)
	{
		if (!AllocConsole())
		{
			return 0;
		}
		else
		{
			stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		}
	}

	if (stdOut == NULL)
	{
		return 0;
	}

	int messageLength = lstrlenA(message);

	int numWritten = 0;

	WriteFile(stdOut, message, messageLength, (LPDWORD)&numWritten, NULL);

	if (numWritten != messageLength)
	{
		return 0;
	}

	return 1;
}

int Console::WriteLine(const char* message)
{
	if (Console::Write(message))
	{
		return Console::Write("\n");
	}

	return 0;
}

int Console::ReadLine(char* buffer, int bufferSize)
{
	HANDLE stdIn = GetStdHandle(STD_INPUT_HANDLE);

	if (stdIn == NULL)
	{
		AllocConsole();

		stdIn = GetStdHandle(STD_INPUT_HANDLE);
	}

	if (stdIn)
	{
		DWORD read;

		RtlSecureZeroMemory(buffer, bufferSize);

		int totalRead = 0;

		char lastChar = 0;

		do
		{
			ReadFile(stdIn, buffer + totalRead, 1, &read, NULL);

			lastChar = *(buffer + totalRead);

			if (lastChar == '\r')
			{
				*(buffer + totalRead) = 0;
				break;
			}

			totalRead += read;
		} while (totalRead < bufferSize - 1);

	}

	return 0;
}