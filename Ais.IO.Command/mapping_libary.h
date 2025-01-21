#pragma once

#include "main.h"

class mapping_libary {
public:
	static char* mapFile(const char* filename, size_t& file_size);
	static void unmapFile(char* map, size_t file_size);
	static void clearScreen();
	static char getKeyPress();
	static void displayHex(char* data, size_t size, int cursorPos);
};

