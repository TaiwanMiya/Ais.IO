#!/bin/bash

Usage() {
    echo "Usage: $0 <operation>"
    echo "Available operations: -w (write), -a (append), -i (insert), -r (read), -rl (read-all), -x (indexes), -d (remove)"
    exit 1
}

if [ "$#" -eq 0 ]; then
    Usage
fi

operation="$1"
file="test.bin"

case "$operation" in
    -w)
        echo "Ais Binary IO Write..."
        ./aisio --write "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
        ;;
    -a)
        echo "Ais Binary IO Append..."
        ./aisio --append "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
        ;;
    -i)
        echo "Ais Binary IO Insert..."
        ./aisio --insert "$file" -bool true 0 -byte 255 0 -sbyte -128 0 -short 32767 0 -ushort 65535 0 -int 2147483647 0 -uint 4294967295 0 -long 9223372036854775807 0 -ulong 18446744073709551615 0 -float 3.1415927 0 -double 3.141592653589793 0 -bytes "This is Ais.IO Function Byte Array." 0 -string "This is Ais.IO Function String." 0
        ;;
    -r)
        echo "Ais Binary IO Read..."
        ./aisio --read "$file" -bool -byte -sbyte -short -ushort -int -uint -long -ulong -float -double -bytes -string
        ;;
    -rl)
        echo "Ais Binary IO Read all..."
        ./aisio --read-all "$file"
        ;;
    -x)
        echo "Ais Binary IO Indexes..."
        ./aisio --indexes "$file"
        ;;
    -d)
        echo "Ais Binary IO Remove..."
        ./aisio --remove "$file" -string 0 32
        ;;
    *)
        Usage
        ;;
esac