#pragma once
class Unmanager
{
public:
	int InjectDLL(int pid, const char* path);
	int GetPidFromProcessName(const wchar_t* name);
};