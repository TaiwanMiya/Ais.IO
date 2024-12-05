dos2unix Ais.IO.Compile.sh
if ! command -v g++ &> /dev/null; then
    echo "g++ Not installed, installing..."
    sudo apt-get update && sudo apt-get install -y g++
else
    echo "g++ Already installed."
fi

sudo apt-get install libssl-dev

cd Ais.IO/ || exit

echo "Start Complie so File..."

if [ ! -d "../unix" ]; then
    echo "Directory bin/unix does not exist. Creating..."
    mkdir -p ../bin/unix
else
    echo "Directory bin/unix already exists."
fi

echo "Complie => Ais.IO.so"
g++ -shared -fPIC BinaryIO.cpp BinaryReaderIO.cpp BinaryWriterIO.cpp BinaryAppenderIO.cpp BinaryInserterIO.cpp EncoderIO.cpp -I./include -o ../bin/unix/Ais.IO.so
cd ../Ais.IO.Command
echo "Complie => aisio"
g++ -o ../unix/aisio output_colors.cpp StringCase.cpp main.cpp
cd ..



#!/bin/bash

# Function to install necessary tools and dependencies
install_dependencies() {
    echo "Installing dependencies..."

    sudo apt install vim
    sudo apt install vim-gtk3
    sudo apt install vim-motif
    sudo apt install vim-nox
    sudo apt install neovim
    dos2unix Ais.IO.Compile.sh
    sudo apt-get update && sudo apt-get install -y g++
    sudo apt-get install libssl-dev
    
    echo "Dependencies installed."
}

# Function to compile the C++ files
compile_cpp() {
    echo "Starting Compilation..."

    # Change to the Ais.IO directory
    cd Ais.IO/ || exit

    echo "Compiling shared library file Ais.IO.so..."

    # Create directory if not exists
    if [ ! -d "../bin/unix" ]; then
        echo "Directory ../bin/unix does not exist. Creating..."
        mkdir -p ../bin/unix
    else
        echo "Directory ../bin/unix already exists."
    fi

    # Compile Ais.IO.so
    g++ -shared -fPIC BinaryIO.cpp BinaryReaderIO.cpp BinaryWriterIO.cpp BinaryAppenderIO.cpp BinaryInserterIO.cpp EncoderIO.cpp -I./include -o ../bin/unix/Ais.IO.so

    # Compile aisio
    cd ../Ais.IO.Command || exit
    echo "Compiling aisio..."
    g++ -o ../bin/unix/aisio output_colors.cpp StringCase.cpp main.cpp
    cd ..

    echo "Compilation finished."
}

# Check provided arguments
if [ "$#" -eq 0 ]; then
    echo "No arguments provided. Please use -i to install dependencies or -c to compile."
    exit 1
fi

while getopts "ic" option; do
    case $option in
        i)
            install_dependencies
            ;;
        c)
            compile_cpp
            ;;
        *)
            echo "Invalid option. Use -i for installing dependencies or -c for compiling."
            exit 1
            ;;
    esac
done
