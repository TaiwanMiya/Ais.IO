echo "Ais Binary IO Write..."
unix/aisio --write test.bin -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
echo "Ais Binary IO Append..."
unix/aisio --append test.bin -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
echo "Ais Binary IO Read..."
unix/aisio --read test.bin -bool -byte -sbyte -short -ushort -int -uint -long -ulong -float -double -bytes -string
echo "Ais Binary IO Read all..."
unix/aisio --read-all test.bin