# Makefile for Ais.IO project

# Compiler and flags
CXX = g++
CXXFLAGS = -shared -fPIC -std=c++17
LDFLAGS = 

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
	@if ! command -v g++ &> /dev/null; then \
		sudo apt-get update && sudo apt-get install -y $(DEPS); \
	else \
		echo "g++ Already installed."; \
	fi
	sudo apt-get install -y $(DEPS)

compile: $(BIN_DIR)/Ais.IO.so $(BIN_DIR)/aisio

$(BIN_DIR)/Ais.IO.so: $(AISO_DIR)/BinaryIO.cpp $(AISO_DIR)/BinaryReaderIO.cpp $(AISO_DIR)/BinaryWriterIO.cpp \
			$(AISO_DIR)/BinaryAppenderIO.cpp $(AISO_DIR)/BinaryInserterIO.cpp $(AISO_DIR)/EncoderIO.cpp
	@echo "Compiling shared library file Ais.IO.so..."
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -I$(AISO_DIR)/include -o $@ -ldl

$(BIN_DIR)/aisio: $(AISO_CMD_DIR)/output_colors.cpp $(AISO_CMD_DIR)/string_case.cpp $(AISO_CMD_DIR)/main.cpp $(AISO_CMD_DIR)/binary_execute.cpp $(AISO_CMD_DIR)/encoder_execute.cpp
	@echo "Compiling aisio..."
	$(CXX) -o $@ $^ -ldl

	@cp -p linux-aisio.sh $(BIN_DIR)/linux-aisio.sh

clean:
	@echo "Cleaning up..."
	@rm -rf $(BIN_DIR)
