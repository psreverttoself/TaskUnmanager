#pragma once

class Console
{
public:
	int Write(const char* message);
	int WriteLine(const char* message);
	int ReadLine(char* buffer, int bufferSize);
};