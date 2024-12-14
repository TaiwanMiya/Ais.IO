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
$encoder = "-e"

# Cryptography Settings...
$KEY = "Key length must be 128, 192, 256"
$IV = "IvMustBe128Size."
$TAG = "TagMustBe128Size"
$AAD = "Additional Authenticated Data (AAD) can be of any length"
$KEY2 = "Secondary Key for AES-XTS Tweak."
$TWEAK = "SectorNumber0001"
$COUNTER = 1
$BASE = "-base16"

$GCM_TAG = "73DD32019CD29E7251D17128DE27FFDD"
$CCM_TAG = "DB9A881B8A159B079F826BD043A4F8C9"
$OCB_TAG = "F7F64A75E6575C9093E12AB272CBF024"
$NONCE = "Nonce12bytes"
$KEK = "This is AES WRAP, 128, 192, 256."
# Parse arguments
while ($args.Count -gt 0) {
    switch ($args[0]) {
        # IO
        '-w' { $operation = '-w'; $args = $args[1..$args.Count]; break }
        '-a' { $operation = '-a'; $args = $args[1..$args.Count]; break }
        '-i' { $operation = '-i'; $args = $args[1..$args.Count]; break }
        '-r' { $operation = '-r'; $args = $args[1..$args.Count]; break }
        '-id' { $operation = '-id'; $args = $args[1..$args.Count]; break }
        '-rm' { $operation = '-rm'; $args = $args[1..$args.Count]; break }
        '-rs' { $operation = '-rs'; $args = $args[1..$args.Count]; break }

        # BASE
        '-b16' { $operation = '-b16'; $args = $args[1..$args.Count]; break }
        '-b32' { $operation = '-b32'; $args = $args[1..$args.Count]; break }
        '-b64' { $operation = '-b64'; $args = $args[1..$args.Count]; break }
        '-b85' { $operation = '-b85'; $args = $args[1..$args.Count]; break }

        #AES
        '-aes-ctr' { $operation = '-aes-ctr'; $args = $args[1..$args.Count]; break }
        '-aes-cbc' { $operation = '-aes-cbc'; $args = $args[1..$args.Count]; break }
        '-aes-cfb' { $operation = '-aes-cfb'; $args = $args[1..$args.Count]; break }
        '-aes-ofb' { $operation = '-aes-ofb'; $args = $args[1..$args.Count]; break }
        '-aes-ecb' { $operation = '-aes-ecb'; $args = $args[1..$args.Count]; break }
        '-aes-gcm' { $operation = '-aes-gcm'; $args = $args[1..$args.Count]; break }
        '-aes-ccm' { $operation = '-aes-ccm'; $args = $args[1..$args.Count]; break }
        '-aes-xts' { $operation = '-aes-xts'; $args = $args[1..$args.Count]; break }
        '-aes-ocb' { $operation = '-aes-ocb'; $args = $args[1..$args.Count]; break }
        '-aes-wrap' { $operation = '-aes-wrap'; $args = $args[1..$args.Count]; break }

        # OTHER
        '-e' { $encoder = '-e'; $args = $args[1..$args.Count]; break }
        '-d' { $encoder = '-d'; $args = $args[1..$args.Count]; break }
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
        # IO
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
        }

        # BASE
        '-b16' {
            if ($encoder -eq '-e') {
                Write-Host "Ais Base 16 Encode..."
                .\aisio "--base16" "-encode" "This is Base16 Encode/Decode."
            }
            else {
                Write-Host "Ais Base 16 Decode..."
                .\aisio "--base16" "-decode" "546869732069732042617365313620456E636F64652F4465636F64652E"
            }
        }
        '-b32' {
            if ($encoder -eq '-e') {
                Write-Host "Ais Base 32 Encode..."
                .\aisio "--base32" "-encode" "This is Base32 Encode/Decode."
            }
            else {
                Write-Host "Ais Base 32 Decode..."
                .\aisio "--base32" "-decode" "KRUGS4ZANFZSAQTBONSTGMRAIVXGG33EMUXUIZLDN5SGKLQ="
            }
        }
        '-b64' {
            if ($encoder -eq '-e') {
                Write-Host "Ais Base 64 Encode..."
                .\aisio "--base64" "-encode" "This is Base64 Encode/Decode."
            }
            else {
                Write-Host "Ais Base 64 Decode..."
                .\aisio "--base64" "-decode" "VGhpcyBpcyBCYXNlNjQgRW5jb2RlL0RlY29kZS4="
            }
        }
        '-b85' {
            if ($encoder -eq '-e') {
                Write-Host "Ais Base 85 Encode..."
                .\aisio "--base85" "-encode" "This is Base85 Encode/Decode."
            }
            else {
                Write-Host "Ais Base 85 Decode..."
                .\aisio "--base85" "-decode" "RA^~)AZc?TLSb`dI5i+eZewp`WiLc!V{c?-E&u=k"
            }
        }

        # AES
        '-aes-ctr' {
            if ($encoder -eq '-e') {
                Write-Host "Ais AES CTR Encrypt..."
                .\aisio --aes -ctr -encrypt -key $KEY -counter $COUNTER -plain-text "This is AES CTR Encryption/Decryption." -out $BASE
            }
            else {
                Write-Host "Ais AES CTR Decrypt..."
                .\aisio --aes -ctr -decrypt -key $KEY -counter $COUNTER -cipher-text $BASE "7F603AB98AF7073B205309B91FCAFC9581DD36055EB25C533429C9EB0C41ACF5070FA94FD62A"
            }
        }
        '-aes-cbc' {
            if ($encoder -eq '-e') {
                Write-Host "Ais AES CBC Encrypt..."
                .\aisio --aes -cbc -encrypt -key $KEY -iv $IV -padding -plain-text "This is AES CBC Encryption/Decryption." -out $BASE
            }
            else {
                Write-Host "Ais AES CBC Decrypt..."
                .\aisio --aes -cbc -decrypt -key $KEY -iv $IV -padding -cipher-text $BASE "FAFEF277E6AF54441F3407175D3860D16BEDC9570CBB83F9609E2CE90AB1596D02167AA72C5A199D7810C0D0FEC674F8"
            }
        }
        '-aes-cfb' {
            if ($encoder -eq '-e') {
                Write-Host "Ais AES CFB Encrypt..."
                .\aisio --aes -cfb -encrypt -key $KEY -iv $IV -segment 128 -plain-text "This is AES CFB Encryption/Decryption." -out $BASE
            }
            else {
                Write-Host "Ais AES CFB Decrypt..."
                .\aisio --aes -cfb -decrypt -key $KEY -iv $IV -segment 128 -cipher-text $BASE "8A30BF00B0F15E4616BF4C9B5742591D658641BE4CE31B24041FA41B791F3021531F171CD401"
            }
        }
        '-aes-ofb' {
            if ($encoder -eq '-e') {
                Write-Host "Ais AES OFB Encrypt..."
                .\aisio --aes -ofb -encrypt -key $KEY -iv $IV -plain-text "This is AES OFB Encryption/Decryption." -out $BASE
            }
            else {
                Write-Host "Ais AES OFB Decrypt..."
                .\aisio --aes -ofb -decrypt -key $KEY -iv $IV -cipher-text $BASE "8A30BF00B0F15E4616BF4C9B5B42591DCF29C1A2F23F43E35CB140041964E890070AAC2913E0"
            }
        }
        '-aes-ecb' {
            if ($encoder -eq '-e') {
                Write-Host "Ais AES ECB Encrypt..."
                .\aisio --aes -ecb -encrypt -key $KEY -padding -plain-text "This is AES ECB Encryption/Decryption." -out $BASE
            }
            else {
                Write-Host "Ais AES ECB Decrypt..."
                .\aisio --aes -ecb -decrypt -key $KEY -padding -cipher-text $BASE "1CD7A6E38BDBDD9F1EFE4BA5A17AB72CDB9CE185F374FBA7DC7C839C5AC30F7CC070E0DD9FA85879BCF8C8049E637406"
            }
        }
        '-aes-gcm' {
            if ($encoder -eq '-e') {
                Write-Host "Ais AES GCM Encrypt..."
                .\aisio --aes -gcm -encrypt -key $KEY -nonce $NONCE -tag $TAG -aad $AAD -plain-text "This is AES GCM Encryption/Decryption." -out $BASE
            }
            else {
                Write-Host "Ais AES GCM Decrypt..."
                .\aisio --aes -gcm -decrypt -key $KEY -nonce $NONCE -tag $BASE $GCM_TAG -aad $AAD -cipher-text $BASE "742389440288A533843D6156F6CC67C28C543B1F397734BA01BE7173FC3E486B70E7A4CD2DF0"
            }
        }
        '-aes-ccm' {
            if ($encoder -eq '-e') {
                Write-Host "Ais AES CCM Encrypt..."
                .\aisio --aes -ccm -encrypt -key $KEY -nonce $NONCE -tag $TAG -aad $AAD -plain-text "This is AES CCM Encryption/Decryption." -out $BASE
            }
            else {
                Write-Host "Ais AES CCM Decrypt..."
                .\aisio --aes -ccm -decrypt -key $KEY -nonce $NONCE -tag $BASE $CCM_TAG -aad $AAD -cipher-text $BASE "5245E1C1520D7BC2E1530310E52BA74D96D1C97A8BE395AF88EEFF71D44BEC2EFEF8F6B65761"
            }
        }
        '-aes-xts' {
            if ($encoder -eq '-e') {
                Write-Host "Ais AES XTS Encrypt..."
                .\aisio --aes -xts -encrypt -key $KEY -key2 $KEY2 -tweak $TWEAK -plain-text "This is AES XTS Encryption/Decryption." -out $BASE
            }
            else {
                Write-Host "Ais AES XTS Decrypt..."
                .\aisio --aes -xts -decrypt -key $KEY -key2 $KEY2 -tweak $TWEAK -cipher-text $BASE "2BC71BB83EEA376368F9429D09470359293905826B14EDA8B170C3E7A4958020C6AF061181B4"
            }
        }
        '-aes-ocb' {
            if ($encoder -eq '-e') {
                Write-Host "Ais AES OCB Encrypt..."
                .\aisio --aes -ocb -encrypt -key $KEY -nonce $NONCE -tag $TAG -aad $AAD -plain-text "This is AES OCB Encryption/Decryption." -out $BASE
            }
            else {
                Write-Host "Ais AES OCB Decrypt..."
                .\aisio --aes -ocb -decrypt -key $KEY -nonce $NONCE -tag $BASE $OCB_TAG -aad $AAD -cipher-text $BASE "3F405A527F7E26DAA3DB8F55D32D33A63C48A9ED40E0ED410CD9E8FC3E090B9627FCC10355A3"
            }
        }
        '-aes-wrap' {
            if ($encoder -eq '-e') {
                Write-Host "Ais AES WRAP Encrypt..."
                .\aisio --aes -wrap -encrypt -key $KEY -kek $KEK -out $BASE
            }
            else {
                Write-Host "Ais AES WRAP Decrypt..."
                .\aisio --aes -wrap -decrypt -wrapkey $BASE "4A0953B24807510E39F18A1AF98153FBA9BF306092D15BB4FB75A04A95148C25B99D7F3A5589FD26" -kek $KEK
            }
        }
        default { Usage }
    }
    
    if ($operation -eq '-rs') {
        break
    }
}
