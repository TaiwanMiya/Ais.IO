if ! command -v g++ &> /dev/null; then
    echo "g++ Not installed, installing..."
    sudo apt-get update && sudo apt-get install -y g++
else
    echo "g++ Already installed."
fi

cd Ais.IO/ || exit

echo "Start Complie so File..."

if [ ! -d "../bin/unix" ]; then
    echo "Directory bin/unix does not exist. Creating..."
    mkdir -p ../bin/unix
else
    echo "Directory bin/unix already exists."
fi

echo "Complie => BinaryIO.so"
g++ -shared -fPIC BinaryIO.cpp -o ../bin/unix/BinaryIO.so
echo "Complie => BinaryReaderIO.so"
g++ -shared -fPIC BinaryReaderIO.cpp -o ../bin/unix/BinaryReaderIO.so
echo "Complie => BinaryWriterIO.so"
g++ -shared -fPIC BinaryWriterIO.cpp -o ../bin/unix/BinaryWriterIO.so

cd ..