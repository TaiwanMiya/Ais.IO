#pragma once

#include "main.h"

class mapping_libary {
public:
	static void ShowHexEditor(const char* fileName);
private:
	static char* mapFile(const char* filename, size_t& file_size);
#if _WIN32
	static wchar_t* convertToWideChar(const char* str);
	static void unmapFile(char* map);
#else
	static void unmapFile(char* map, size_t file_size);
#endif
	static void clearScreen();
	static char getKeyPress();
	static void displayHex(char* data, size_t size, int cursorPos);
};

