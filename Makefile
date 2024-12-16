# Makefile for Ais.IO project

# Compiler and flags
CXX = g++
CXXFLAGS = -shared -fPIC -std=c++17
LIB_PATHS := $(shell find /usr -name "libcrypto.so" -o -name "libssl.so" | xargs -n 1 dirname | sort -u)
LDFLAGS += $(addprefix -L, $(LIB_PATHS))
LIBS += -lcrypto -lssl

# Detect platform
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Linux)
    CXXFLAGS += -DUSE_TRUNCATE
endif

# Directories
AISO_DIR = Ais.IO
AISO_CMD_DIR = Ais.IO.Command
BIN_DIR = unix

# Dependencies
DEPS = libssl-dev g++

.PHONY: all install_deps compile clean

all: install_deps compile

install_deps:
	@echo "Checking and installing dependencies..."
	@if ! command -v g++ 2>&1; then \
		sudo apt-get update && sudo apt-get install -y $(DEPS); \
	else \
		echo "g++ Already installed."; \
	fi
	@if ! command -v openssl 2>&1; then \
		sudo apt-get update && sudo apt-get install -y $(DEPS); \
	else \
		echo "openssl Already installed."; \
	fi

compile: $(BIN_DIR)/Ais.IO.so $(BIN_DIR)/aisio

$(BIN_DIR)/Ais.IO.so: $(AISO_DIR)/BinaryIO.cpp $(AISO_DIR)/BinaryReaderIO.cpp $(AISO_DIR)/BinaryWriterIO.cpp \
			$(AISO_DIR)/BinaryAppenderIO.cpp $(AISO_DIR)/BinaryInserterIO.cpp $(AISO_DIR)/BaseEncoderIO.cpp \
			$(AISO_DIR)/AsymmetricIO.cpp $(AISO_DIR)/AesIO.cpp $(AISO_DIR)/DesIO.cpp
	@echo "Compiling shared library file Ais.IO.so..."
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -I$(AISO_DIR)/include -o $@ $(LIBS) -ldl

$(BIN_DIR)/aisio: $(AISO_CMD_DIR)/output_colors.cpp $(AISO_CMD_DIR)/string_case.cpp $(AISO_CMD_DIR)/main.cpp \
			$(AISO_CMD_DIR)/binary_execute.cpp $(AISO_CMD_DIR)/encoder_execute.cpp $(AISO_CMD_DIR)/aes_execute.cpp $(AISO_CMD_DIR)/des_execute.cpp \
			$(AISO_CMD_DIR)/cryptography_libary.cpp
	@echo "Compiling aisio..."
	$(CXX) -o $@ $^ -ldl

	@cp -p Terminal/Linux/linux-aisio.sh $(BIN_DIR)/linux-aisio.sh
	@cp -p Terminal/Linux/terminal-colors.sh $(BIN_DIR)/colors.sh
	@chmod +x $(BIN_DIR)/linux-aisio.sh
	@chmod +x $(BIN_DIR)/colors.sh

clean:
	@echo "Cleaning up..."
	@rm -rf $(BIN_DIR)
