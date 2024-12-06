#!/bin/bash

Usage() {
    echo "Usage: $0 <operation> [-f <filename>] [-n <iterations>]"
    echo "Available operations: -w (write), -a (append), -i (insert), -r (read), -rl (read-all), -x (indexes), -d (remove)"
    exit 1
}

# 设置默认值
file="test.bin"
iterations=1

# 检查参数是否提供
if [ "$#" -eq 0 ]; then
    Usage
fi

# 解析参数
operation=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -w|-a|-i|-r|-rl|-x|-d)
            operation="$1"
            shift
            ;;
        -f)
            file="$2"
            shift 2
            ;;
        -n)
            iterations="$2"
            shift 2
            ;;
        *)
            Usage
            ;;
    esac
done

# 检查是否指定操作
if [ -z "$operation" ]; then
    echo "Error: Operation is required."
    Usage
fi

# 执行操作多次
for ((i=1; i<=iterations; i++)); do
    echo "Iteration $i/$iterations"
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
done

