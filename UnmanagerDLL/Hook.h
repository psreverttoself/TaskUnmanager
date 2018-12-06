#pragma once

struct HookStruct32
{
	char Valid = 0;
	char OriginalBytes[6];
	char ReplacementBytes[6];
	void* OriginalFunction;
	void* OriginalFunctionAddress;
};

struct HookStruct64
{
	char Valid = 0;
	char OriginalBytes[12];
	char ReplacementBytes[12];
	void* OriginalFunction;
	void* OriginalFunctionAddress;
};