#pragma once
#include "main.h"

class binary_execute {
public:
	static std::string GetTypeName(BINARYIO_TYPE type);
    static void ReadToType(void* reader, BINARYIO_TYPE type, uint64_t& count);
    static void GetIndexes(void* reader);
    static void ExecuteRead(void* reader, const std::vector<Command>& commands);
    static void ExecuteWrite(void* writer, const std::vector<Command>& commands);
    static void ExecuteAppend(void* appender, const std::vector<Command>& commands);
    static void ExecuteInsert(void* inserter, const std::vector<Command>& commands);
    static void ExecuteRemove(void* remover, const std::string filePath, const std::vector<Command>& commands);
};

