function Usage {
    $scriptName = ".\$(Split-Path -Path $PSCommandPath -Leaf)"
    Write-Host "Usage:"
    Write-Host "    $scriptName <operation> [-f <filename>] [-n <iterations>]"
    Write-Host "Available operations:"
    Write-Host "    -w  (write)"
    Write-Host "    -a  (append)"
    Write-Host "    -i  (insert)"
    Write-Host "    -r  (read-all)"
    Write-Host "    -id (indexes)"
    Write-Host "    -rm (remove)"
    Write-Host "    -rs (remove-index)"
    Read-Host "Press Enter to exit" | Out-Null
    exit
}

$file = "test.bin"
$iterations = 1

if ($args.Count -eq 0) {
    Usage
}

$operation = ""
$indexList = ""

# Parse arguments
while ($args.Count -gt 0) {
    switch ($args[0]) {
        '-w' { $operation = '-w'; $args = $args[1..$args.Count]; break }
        '-a' { $operation = '-a'; $args = $args[1..$args.Count]; break }
        '-i' { $operation = '-i'; $args = $args[1..$args.Count]; break }
        '-r' { $operation = '-r'; $args = $args[1..$args.Count]; break }
        '-id' { $operation = '-id'; $args = $args[1..$args.Count]; break }
        '-rm' { $operation = '-rm'; $args = $args[1..$args.Count]; break }
        '-rs' { $operation = '-rs'; $args = $args[1..$args.Count]; break }
        '-f' {
            if ($args.Count -gt 1) {
                $file = $args[1]
                $args = $args[2..$args.Count]
            } else {
                Usage
            }
            break
        }
        '-n' {
            if ($args.Count -gt 1) {
                $iterations = [int]$args[1]
                $args = $args[2..$args.Count]
            } else {
                Usage
            }
            break
        }
        default { Usage }
    }
}

if (-not $operation) {
    Write-Host "Error: Operation is required."
    Usage
}

if (-not $iterations -or $iterations -lt 1) {
    Write-Error "Iterations must be a positive integer."
    exit
}

# Generate index list
$indexList = (0..($iterations - 1)) -join " "

for ($i = 1; $i -le $iterations; $i++) {
    if ($operation -ne '-rs') {
        Write-Host "Iteration $i/$iterations"
    }
    else {
        Write-Host "Iteration $i/1"
    }
    switch ($operation) {
        '-w' {
            Write-Host "Ais Binary IO Write..."
            .\aisio --write $file -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
        }
        '-a' {
            Write-Host "Ais Binary IO Append..."
            .\aisio --append $file -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
        }
        '-i' {
            Write-Host "Ais Binary IO Insert..."
            .\aisio --insert $file -bool true 0 -byte 255 0 -sbyte -128 0 -short 32767 0 -ushort 65535 0 -int 2147483647 0 -uint 4294967295 0 -long 9223372036854775807 0 -ulong 18446744073709551615 0 -float 3.1415927 0 -double 3.141592653589793 0 -bytes "This is Ais.IO Function Byte Array." 0 -string "This is Ais.IO Function String." 0
        }
        '-r' {
            Write-Host "Ais Binary IO Read all..."
            $arguments = @("--read-all", $file)
            Start-Process -FilePath "./aisio" -ArgumentList $arguments -NoNewWindow -Wait
        }
        '-id' {
            Write-Host "Ais Binary IO Indexes..."
            $arguments = @("--indexes", $file)
            Start-Process -FilePath "./aisio" -ArgumentList $arguments -NoNewWindow -Wait
        }
        '-rm' {
            Write-Host "Ais Binary IO Remove..."
            $arguments = @("--remove", $file, "-string 0 32")
            Start-Process -FilePath "./aisio" -ArgumentList $arguments -NoNewWindow -Wait
        }
        '-rs' {
            Write-Host "Ais Binary IO Remove Index..."
            $arguments = @("--remove-index", $file, $indexList)
            Start-Process -FilePath "./aisio" -ArgumentList $arguments -NoNewWindow -Wait
            break
        }
        default { Usage }
    }
    
    if ($operation -eq '-rs') {
        break
    }
}
