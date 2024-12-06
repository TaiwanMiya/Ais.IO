# Makefile for Ais.IO project

# Compiler and flags
CXX = g++
CXXFLAGS = -shared -fPIC

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
	$(CXX) $(CXXFLAGS) $^ -I$(AISO_DIR)/include -o $@

$(BIN_DIR)/aisio: $(AISO_CMD_DIR)/output_colors.cpp $(AISO_CMD_DIR)/StringCase.cpp $(AISO_CMD_DIR)/main.cpp
	@echo "Compiling aisio..."
	$(CXX) -o $@ $^

	@cp -p linux-aisio.sh $(BIN_DIR)/linux-aisio.sh

clean:
	@echo "Cleaning up..."
	@rm -rf $(BIN_DIR)
