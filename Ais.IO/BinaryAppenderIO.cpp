#include "pch.h"
#include "BinaryAppenderIO.h"
#include "BinaryIO.h"

#ifndef APPEND_CAST 
#define APPEND_CAST reinterpret_cast<const char*>
#endif // !APPEND_CAST

class BinaryAppender {
public:
	BinaryAppender(const std::string& filePath) {
		OutputStream.open(filePath, std::ios::binary | std::ios::app);
		if (!OutputStream.is_open())
			throw std::runtime_error("Unable to open file for appending.");
	}

	~BinaryAppender() {
		if (OutputStream.is_open())
			OutputStream.close();
	}

	uint64_t GetPosition() {
		if (!OutputStream.is_open())
			throw std::runtime_error("Output stream is not open.");
		return static_cast<uint64_t>(OutputStream.tellp());
	}

	uint64_t GetLength() {
		if (!OutputStream.is_open())
			throw std::runtime_error("Output stream is not open.");
		std::streampos currentPos = OutputStream.tellp();
		OutputStream.seekp(0, std::ios::end);
		std::streampos endPos = OutputStream.tellp();
		OutputStream.seekp(currentPos, std::ios::beg);
		return static_cast<uint64_t>(endPos);
	}

    void AppendBoolean(bool value) {
        AppendType(BINARYIO_TYPE::TYPE_BOOLEAN);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendByte(unsigned char value) {
        AppendType(BINARYIO_TYPE::TYPE_BYTE);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendSByte(signed char value) {
        AppendType(BINARYIO_TYPE::TYPE_SBYTE);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendShort(short value) {
        AppendType(BINARYIO_TYPE::TYPE_SHORT);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendUShort(unsigned short value) {
        AppendType(BINARYIO_TYPE::TYPE_USHORT);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendInt(int value) {
        AppendType(BINARYIO_TYPE::TYPE_INT);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendUInt(unsigned int value) {
        AppendType(BINARYIO_TYPE::TYPE_UINT);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendLong(long long value) {
        AppendType(BINARYIO_TYPE::TYPE_LONG);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendULong(unsigned long long value) {
        AppendType(BINARYIO_TYPE::TYPE_ULONG);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendFloat(float value) {
        AppendType(BINARYIO_TYPE::TYPE_FLOAT);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendDouble(double value) {
        AppendType(BINARYIO_TYPE::TYPE_DOUBLE);
        OutputStream.write(APPEND_CAST(&value), sizeof(value));
    }

    void AppendBytes(const unsigned char* bytes, uint64_t length) {
        AppendType(BINARYIO_TYPE::TYPE_BYTES);
        OutputStream.write(APPEND_CAST(&length), sizeof(length));
        OutputStream.write(APPEND_CAST(bytes), length);
    }

    void AppendString(const std::string& value) {
        AppendType(BINARYIO_TYPE::TYPE_STRING);
        uint64_t length = value.length() + 1;
        OutputStream.write(APPEND_CAST(&length), sizeof(length));
        OutputStream.write(value.data(), length);
    }
private:
	std::ofstream OutputStream;

	void AppendType(BINARYIO_TYPE type) {
		OutputStream.write(APPEND_CAST(&type), sizeof(type));
	}
};

/* Appender Interface */

void* CreateBinaryAppender(const char* filePath) {
    try {
        return new BinaryAppender(filePath);
    }
    catch (...) {
        return nullptr;
    }
}

void DestroyBinaryAppender(void* appender) {
    delete static_cast<BinaryAppender*>(appender);
}

uint64_t GetAppenderPosition(void* appender) {
    return static_cast<BinaryAppender*>(appender)->GetPosition();
}

uint64_t GetAppenderLength(void* appender) {
    return static_cast<BinaryAppender*>(appender)->GetLength();
}

void AppendBoolean(void* appender, bool value) {
    static_cast<BinaryAppender*>(appender)->AppendBoolean(value);
}

void AppendByte(void* appender, unsigned char value) {
    static_cast<BinaryAppender*>(appender)->AppendByte(value);
}

void AppendSByte(void* appender, signed char value) {
    static_cast<BinaryAppender*>(appender)->AppendSByte(value);
}

void AppendShort(void* appender, short value) {
    static_cast<BinaryAppender*>(appender)->AppendShort(value);
}

void AppendUShort(void* appender, unsigned short value) {
    static_cast<BinaryAppender*>(appender)->AppendUShort(value);
}

void AppendInt(void* appender, int value) {
    static_cast<BinaryAppender*>(appender)->AppendInt(value);
}

void AppendUInt(void* appender, unsigned int value) {
    static_cast<BinaryAppender*>(appender)->AppendUInt(value);
}

void AppendLong(void* appender, long long value) {
    static_cast<BinaryAppender*>(appender)->AppendLong(value);
}

void AppendULong(void* appender, unsigned long long value) {
    static_cast<BinaryAppender*>(appender)->AppendULong(value);
}

void AppendFloat(void* appender, float value) {
    static_cast<BinaryAppender*>(appender)->AppendFloat(value);
}

void AppendDouble(void* appender, double value) {
    static_cast<BinaryAppender*>(appender)->AppendDouble(value);
}

void AppendBytes(void* appender, const unsigned char* bytes, uint64_t length) {
    static_cast<BinaryAppender*>(appender)->AppendBytes(bytes, length);
}

void AppendString(void* appender, const char* value) {
    static_cast<BinaryAppender*>(appender)->AppendString(std::string(value));
}