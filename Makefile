# Makefile for Ais.IO project

# Compiler and flags
CXX = g++
CXXFLAGS = -shared -fPIC -std=c++17
LIB_PATHS := Ais.IO/so
LDFLAGS += -L$(LIB_PATHS) -Wl,--whole-archive $(LIB_PATHS)/libcrypto.a $(LIB_PATHS)/libssl.a -Wl,--no-whole-archive
LIBS = -ldl

# Detect platform
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Linux)
    CXXFLAGS += -DUSE_TRUNCATE
endif

# Directories
AISO_DIR = Ais.IO
AISO_CMD_DIR = Ais.IO.Command
BIN_DIR = unix
GUI_DIR        = aisio-gui
GUI_BUILD_DIR  = $(GUI_DIR)/build
CMAKE_FLAGS    ?= -DCMAKE_BUILD_TYPE=Release -DAISIO_USE_PREBUILT=OFF

# Dependencies
DEPS = libssl-dev g++
DOS2 = dos2unix
VIM = vim vim-gtk3 vim-motif vim-nox neovim

.PHONY: all install_deps compile clean

all: install_deps compile

install_deps:
	@echo "Checking and installing dependencies..."
	@if ! command -v g++ 2>&1; then \
		sudo apt update && sudo apt install -y $(DEPS); \
	else \
		echo "g++ Already installed."; \
	fi
	@if ! command -v openssl 2>&1; then \
		sudo apt update && sudo apt install -y $(DEPS); \
	else \
		echo "openssl Already installed."; \
	fi
	@if ! command -v dos2unix 2>&1; then \
		sudo apt update && sudo apt install -y dos2unix; \
	else \
		echo "dos2unix Already installed."; \
	fi
	@if ! command -v vim 2>&1; then \
		sudo apt update && sudo apt install $(VIM); \
	else \
		echo "vim Already installed."; \
	fi
	@if ! command -v whiptail 2>&1; then \
		sudo apt update && sudo apt install whiptail; \
	else \
		echo "whiptail Already installed."; \
	fi
	@if ! command -v apt-cache show qt6-base-dev >/dev/null 2>&1; then \
		sudo apt update && sudo apt install qt6-base-dev qt6-tools-dev qt6-tools-dev-tools \
	else \
		echo "qt6-base Already installed."; \
	fi


compile: $(BIN_DIR)/Ais.IO.so $(BIN_DIR)/aisio

$(BIN_DIR)/Ais.IO.so: $(AISO_DIR)/BinaryIO.cpp $(AISO_DIR)/BinaryReaderIO.cpp $(AISO_DIR)/BinaryWriterIO.cpp \
			$(AISO_DIR)/BinaryAppenderIO.cpp $(AISO_DIR)/BinaryInserterIO.cpp $(AISO_DIR)/BaseEncoderIO.cpp \
			$(AISO_DIR)/CheckValid.cpp \
			$(AISO_DIR)/SymmetryIO.cpp $(AISO_DIR)/AsymmetricIO.cpp \
			$(AISO_DIR)/AesIO.cpp $(AISO_DIR)/DesIO.cpp \
			$(AISO_DIR)/HashIO.cpp \
			$(AISO_DIR)/DsaIO.cpp $(AISO_DIR)/RsaIO.cpp $(AISO_DIR)/EccIO.cpp
	@echo "Compiling shared library file Ais.IO.so..."
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -I$(AISO_DIR)/include -o $@ $(LIBS)

$(BIN_DIR)/aisio: $(AISO_CMD_DIR)/output_colors.cpp $(AISO_CMD_DIR)/string_case.cpp $(AISO_CMD_DIR)/main.cpp $(AISO_CMD_DIR)/usage_libary.cpp \
			$(AISO_CMD_DIR)/binary_execute.cpp $(AISO_CMD_DIR)/encoder_execute.cpp \
			$(AISO_CMD_DIR)/mapping_libary.cpp \
			$(AISO_CMD_DIR)/asymmetric_libary.cpp \
			$(AISO_CMD_DIR)/aes_execute.cpp $(AISO_CMD_DIR)/des_execute.cpp \
			$(AISO_CMD_DIR)/hash_execute.cpp \
			$(AISO_CMD_DIR)/dsa_execute.cpp $(AISO_CMD_DIR)/rsa_execute.cpp $(AISO_CMD_DIR)/ecc_execute.cpp \
			$(AISO_CMD_DIR)/cryptography_libary.cpp
	@echo "Compiling aisio..."
	$(CXX) -o $@ $^ -ldl

	@echo "==> [GUI] CMake configure at $(GUI_BUILD_DIR)"
	@mkdir -p "$(GUI_BUILD_DIR)"
	@cmake -S "$(GUI_DIR)" -B "$(GUI_BUILD_DIR)" $(CMAKE_FLAGS)
	@echo "==> [GUI] CMake build -j$(JOBS)"
	@cmake --build "$(GUI_BUILD_DIR)" -j$(JOBS)

	@dos2unix Terminal/Linux/*.sh
	@dos2unix *.sh
	@dos2unix Makefile
	@chmod 777 Terminal/Linux/*.sh
	@chmod 777 *.sh
	@cp -p Terminal/Linux/*.sh $(BIN_DIR)/
	@chmod 777 $(BIN_DIR)/*.sh

clean:
	@echo "Cleaning up..."
	@rm -rf $(BIN_DIR)
	@rm -rf "$(GUI_BUILD_DIR)"