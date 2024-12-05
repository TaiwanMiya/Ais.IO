@echo off
chcp 65001

echo "Ais Binary IO Write..."
aisio --write test.bin -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
echo "Ais Binary IO Append..."
aisio --append test.bin -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
echo "Ais Binary IO Insert..."
aisio --insert test.bin -bool true 0 -byte 255 0 -sbyte -128 0 -short 32767 0 -ushort 65535 0 -int 2147483647 0 -uint 4294967295 0 -long 9223372036854775807 0 -ulong 18446744073709551615 0 -float 3.1415927 0 -double 3.141592653589793 0 -bytes "This is Ais.IO Function Byte Array." 0 -string "This is Ais.IO Function String." 0
echo "Ais Binary IO Read..."
aisio --read test.bin -bool -byte -sbyte -short -ushort -int -uint -long -ulong -float -double -bytes -string
echo "Ais Binary IO Read all..."
aisio --read-all test.bin
echo "Ais Binary IO Indexes..."
aisio --indexes test.bin
echo "Ais Binary IO Remove..."
aisio --remove test.bin -string 0 32

echo on