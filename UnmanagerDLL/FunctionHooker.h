#pragma once
#include "Hook.h"

class FunctionHooker
{
public:
	int HookFunction32(void* hookedFunctionAddress, void* replacementFunctionAddress, HookStruct32* hook);
	int HookFunction64(void* hookedFunctionAddress, void* replacementFunctionAddress, HookStruct64* hook);
	int UnhookFunction32(HookStruct32* hook);
	int UnhookFunction64(HookStruct64* hook);
};