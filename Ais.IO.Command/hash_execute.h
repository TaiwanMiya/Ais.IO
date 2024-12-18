#pragma once
#include "main.h"

class hash_execute {
public:
	static void ParseParameters(int argc, char* argv[], Hashes& hash);
	static void HashStart(Hashes& hash);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
};

