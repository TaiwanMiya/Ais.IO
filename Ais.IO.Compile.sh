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
g++ -shared -fPIC BinaryIO.cpp BinaryReaderIO.cpp BinaryWriterIO.cpp EncoderIO.cpp -I./include -o ../unix/Ais.IO.so
cd ../Ais.IO.Command
echo "Complie => aisio"
g++ -o ../unix/aisio StringCase.cpp main.cpp
cd ..
