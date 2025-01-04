#pragma once
#include "main.h"

class binary_execute {
public:
	static std::string GetTypeName(BINARYIO_TYPE type);
    static void ReadToType(void* reader, BINARYIO_TYPE type, uint64_t& count, std::string& message, CRYPT_OPTIONS bytes_option);
    static void GetIndexes(void* reader);
    static void ExecuteRead(void* reader, const std::vector<Command>& commands, CRYPT_OPTIONS bytes_option);
    static void ExecuteWrite(void* writer, const std::vector<Command>& commands, CRYPT_OPTIONS bytes_option);
    static void ExecuteAppend(void* appender, const std::vector<Command>& commands, CRYPT_OPTIONS bytes_option);
    static void ExecuteInsert(void* inserter, const std::vector<Command>& commands, CRYPT_OPTIONS bytes_option);
    static void ExecuteRemove(void* remover, const std::string filePath, const std::vector<Command>& commands);
    static void ExecuteRemoveIndex(void* reader, void* remover, const std::string filePath, const std::vector<Command>& commands);
    static void ExecuteReadIndex(void* reader, void* index_reader, const std::string filePath, const std::vector<Command>& commands, std::string& message, CRYPT_OPTIONS bytes_option);
};

