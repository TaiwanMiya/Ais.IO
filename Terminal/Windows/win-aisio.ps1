. .\Aisio-powershell-function.ps1

$file = "test.bin"
$iterations = 1

if ($args.Count -eq 0) {
    Usage
}

$operation = ""
$indexList = ""
$encoder = "-e"
$mode=""
$rsa_format="-pem"

$startTime = [datetime]::UtcNow
$parameter = $args.Clone()
# Parse arguments
while ($parameter.Count -gt 0) {
    switch ($parameter[0]) {
        # IO
        '-w'    { $operation = '-w';                $parameter = $parameter[1..$parameter.Count]; break }
        '-a'    { $operation = '-a';                $parameter = $parameter[1..$parameter.Count]; break }
        '-i'    { $operation = '-i';                $parameter = $parameter[1..$parameter.Count]; break }
        '-r'    { $operation = '-r';                $parameter = $parameter[1..$parameter.Count]; break }
        '-id'   { $operation = '-id';               $parameter = $parameter[1..$parameter.Count]; break }
        '-rm'   { $operation = '-rm';               $parameter = $parameter[1..$parameter.Count]; break }
        '-rs'   { $operation = '-rs';               $parameter = $parameter[1..$parameter.Count]; break }
        '-ri'   { $operation = '-ri';               $parameter = $parameter[1..$parameter.Count]; break }

        # BASE
        '-b10'  { $operation = '-b10';              $parameter = $parameter[1..$parameter.Count]; break }
        '-b16'  { $operation = '-b16';              $parameter = $parameter[1..$parameter.Count]; break }
        '-b32'  { $operation = '-b32';              $parameter = $parameter[1..$parameter.Count]; break }
        '-b58'  { $operation = '-b58';              $parameter = $parameter[1..$parameter.Count]; break }
        '-b62'  { $operation = '-b62';              $parameter = $parameter[1..$parameter.Count]; break }
        '-b64'  { $operation = '-b64';              $parameter = $parameter[1..$parameter.Count]; break }
        '-b85'  { $operation = '-b85';              $parameter = $parameter[1..$parameter.Count]; break }
        '-b91'  { $operation = '-b91';              $parameter = $parameter[1..$parameter.Count]; break }

        # RAND
        '-gen'  { if ($operation -eq '-rsa') { $mode = '-gen'; } else { $operation = '-gen'; }
                                                    $parameter = $parameter[1..$parameter.Count]; break }
        '-imp'  { $operation = '-imp';              $parameter = $parameter[1..$parameter.Count]; break }
        '-exp'  { $mode = '-exp';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-ext'  { $mode = '-ext';                   $parameter = $parameter[1..$parameter.Count]; break }

        # AES
        '-aes'  { $operation = '-aes';              $parameter = $parameter[1..$parameter.Count]; break }
        
        '-ctr'  { $mode = '-ctr';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-cbc'  { $mode = '-cbc';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-cfb'  { $mode = '-cfb';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-ofb'  { $mode = '-ofb';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-ecb'  { $mode = '-ecb';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-gcm'  { $mode = '-gcm';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-ccm'  { $mode = '-ccm';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-xts'  { $mode = '-xts';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-ocb'  { $mode = '-ocb';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-wrap' { $mode = '-wrap';                  $parameter = $parameter[1..$parameter.Count]; break }
        
        # DES
        '-des'  { $operation = '-des';              $parameter = $parameter[1..$parameter.Count]; break }

        '-cbc'  { $mode = '-cbc';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-cfb'  { $mode = '-cfb';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-ofb'  { $mode = '-ofb';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-ecb'  { $mode = '-ecb';                   $parameter = $parameter[1..$parameter.Count]; break }
        '-wrap' { $mode = '-wrap';                  $parameter = $parameter[1..$parameter.Count]; break }

        # HASH
        '-hash' { $operation = '-hash';             $parameter = $parameter[1..$parameter.Count]; break }
        
        '-md5'          { $mode = '-md5';           $parameter = $parameter[1..$parameter.Count]; break }
        '-md5-sha1'     { $mode = '-md5-sha1';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha1'         { $mode = '-sha1';          $parameter = $parameter[1..$parameter.Count]; break }
        '-sha224'       { $mode = '-sha2-224';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha2-224'     { $mode = '-sha2-224';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha256'       { $mode = '-sha2-256';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha2-256'     { $mode = '-sha2-256';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha384'       { $mode = '-sha2-384';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha2-384'     { $mode = '-sha2-384';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha512'       { $mode = '-sha2-512';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha2-512'     { $mode = '-sha2-512';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha512-224'   { $mode = '-sha2-512-224';  $parameter = $parameter[1..$parameter.Count]; break }
        '-sha2-512-224' { $mode = '-sha2-512-224';  $parameter = $parameter[1..$parameter.Count]; break }
        '-sha512-256'   { $mode = '-sha2-512-256';  $parameter = $parameter[1..$parameter.Count]; break }
        '-sha2-512-256' { $mode = '-sha2-512-256';  $parameter = $parameter[1..$parameter.Count]; break }
        '-sha3-224'     { $mode = '-sha3-224';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha3-256'     { $mode = '-sha3-256';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha3-384'     { $mode = '-sha3-384';      $parameter = $parameter[1..$parameter.Count]; break }
        '-sha3-512'     { $mode = '-sha3-512';      $parameter = $parameter[1..$parameter.Count]; break }
        '-shake128'     { $mode = '-sha3-ke-128';   $parameter = $parameter[1..$parameter.Count]; break }
        '-sha3-ke-128'  { $mode = '-sha3-ke-128';   $parameter = $parameter[1..$parameter.Count]; break }
        '-shake256'     { $mode = '-sha3-ke-256';   $parameter = $parameter[1..$parameter.Count]; break }
        '-sha3-ke-256'  { $mode = '-sha3-ke-256';   $parameter = $parameter[1..$parameter.Count]; break }
        '-blake2s'      { $mode = '-blake2s-256';   $parameter = $parameter[1..$parameter.Count]; break }
        '-blake256'     { $mode = '-blake2s-256';   $parameter = $parameter[1..$parameter.Count]; break }
        '-blake2s-256'  { $mode = '-blake2s-256';   $parameter = $parameter[1..$parameter.Count]; break }
        '-blake2b'      { $mode = '-blake2b-512';   $parameter = $parameter[1..$parameter.Count]; break }
        '-blake512'     { $mode = '-blake2b-512';   $parameter = $parameter[1..$parameter.Count]; break }
        '-blake2b-512'  { $mode = '-blake2b-512';   $parameter = $parameter[1..$parameter.Count]; break }
        '-sm3'          { $mode = '-sm3';           $parameter = $parameter[1..$parameter.Count]; break }
        '-ripemd160'    { $mode = '-ripemd160';     $parameter = $parameter[1..$parameter.Count]; break }

        # RSA
        '-rsa'  { $operation = '-rsa';              $parameter = $parameter[1..$parameter.Count]; break }

        '-pem'          { $rsa_format = '-pem';     $parameter = $parameter[1..$parameter.Count]; break }
        '-der'          { $rsa_format = '-der';     $parameter = $parameter[1..$parameter.Count]; break }
        '-param'        { $rsa_format = '-param';   $parameter = $parameter[1..$parameter.Count]; break }
        '-chk'          { $mode = '-chk';           $parameter = $parameter[1..$parameter.Count]; break }

        # OTHER
        # '-e' { $encoder = '-e';                     $parameter = $parameter[1..$parameter.Count]; break }
        '-e' { if ($operation -eq '-rsa') { $mode = '-crypt'; }
               $encoder = '-e';                     $parameter = $parameter[1..$parameter.Count]; break }
        '-d' { if ($operation -eq '-rsa') { $mode = '-crypt'; }
               $encoder = '-d';                     $parameter = $parameter[1..$parameter.Count]; break }
        '-s' { if ($operation -eq '-rsa') { $mode = '-digital'; }
               $encoder = '-s';                     $parameter = $parameter[1..$parameter.Count]; break }
        '-v' { if ($operation -eq '-rsa') { $mode = '-digital'; }
               $encoder = '-v';                     $parameter = $parameter[1..$parameter.Count]; break }
        '-f' {
            if ($parameter.Count -gt 1) {
                $file = $parameter[1]
                $parameter = $parameter[2..$parameter.Count]
            } else {
                Usage
            }
            break
        }
        '-n' {
            if ($parameter.Count -gt 1) {
                $iterations = [int]$parameter[1]
                $parameter = $parameter[2..$parameter.Count]
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
    if ($operation -ne '-rs' -and $operation -ne '-ri') { Write-Host "Iteration $i/$iterations" }
    else { Write-Host "Iteration $i/1" }
    switch ($operation) {
        # IO
        '-w'    { BinaryWrite }
        '-a'    { BinaryAppend }
        '-i'    { BinaryInsert }
        '-r'    { BinaryReadAll }
        '-id'   { BinaryIndexes }
        '-rm'   { BinaryRemove }
        '-rs'   { BinaryRemoveIndex }
        '-ri'   { BinaryReadIndex }

        # BASE
        '-b10'  { BASE_10 }
        '-b16'  { BASE_16 }
        '-b32'  { BASE_32 }
        '-b58'  { BASE_58 }
        '-b62'  { BASE_62 }
        '-b64'  { BASE_64 }
        '-b85'  { BASE_85 }
        '-b91'  { BASE_91 }

        # RAND
        '-gen'  { Generate }
        '-imp'  { Import }

        # AES
        '-aes' {
            switch ($mode) {
                '-ctr'  { AES_CTR }
                '-cbc'  { AES_CBC }
                '-cfb'  { AES_CFB }
                '-ofb'  { AES_OFB }
                '-ecb'  { AES_ECB }
                '-gcm'  { AES_GCM }
                '-ccm'  { AES_CCM }
                '-xts'  { AES_XTS }
                '-ocb'  { AES_OCB }
                '-wrap' { AES_WRAP }
                default { Usage }
            }
        }

        # DES
        '-des' {
            switch ($mode) {
                '-cbc'  { DES_CBC }
                '-cfb'  { DES_CFB }
                '-ofb'  { DES_OFB }
                '-ecb'  { DES_ECB }
                '-wrap' { DES_WRAP }
                default { Usage }
            }
        }

        # HASH
        '-hash' {
            switch ($mode) {
                '-md5'              { HASH_MD5 }
                '-md5-sha1'         { HASH_MD5_SHA1 }
                '-sha1'             { HASH_SHA1 }
                '-sha2-224'         { HASH_SHA2_224 }
                '-sha2-256'         { HASH_SHA2_256 }
                '-sha2-384'         { HASH_SHA2_384 }
                '-sha2-512'         { HASH_SHA2_512 }
                '-sha2-512-224'     { HASH_SHA2_512_224 }
                '-sha2-512-256'     { HASH_SHA2_512_256 }
                '-sha3-224'         { HASH_SHA3_224 }
                '-sha3-256'         { HASH_SHA3_256 }
                '-sha3-384'         { HASH_SHA3_384 }
                '-sha3-512'         { HASH_SHA3_512 }
                '-sha3-ke-128'      { HASH_SHA3_KE_128 }
                '-sha3-ke-256'      { HASH_SHA3_KE_256 }
                '-blake2s-256'      { HASH_BLAKE2S_256 }
                '-blake2b-512'      { HASH_BLAKE2B_512 }
                '-sm3'              { HASH_SM3 }
                '-ripemd160'        { HASH_RIPEMD160 }
            }
        }

        '-rsa' {
            switch ($mode) {
                '-gen' {
                    switch ($rsa_format) {
                        '-pem'      { RSA_Generate_Keys_PEM }
                        '-der'      { RSA_Generate_Keys_DER }
                        '-param'    { RSA_Generate_Paramters }
                    }
                }
                '-exp' {
                    switch ($rsa_format) {
                        '-pem'      { RSA_Export_Keys_PEM }
                        '-der'      { RSA_Export_Keys_DER }
                        '-param'    { RSA_Export_Paramters }
                    }
                }
                '-ext' {
                    switch ($rsa_format) {
                        '-pem'      { RSA_Extract_Public_Key_PEM }
                        '-der'      { RSA_Extract_Public_Key_DER }
                    }
                }
                '-chk' {
                    switch ($rsa_format) {
                        '-pem'      { RSA_Check_Keys_PEM }
                        '-der'      { RSA_Check_Keys_DER }
                    }
                }
                '-crypt' {
                    switch ($rsa_format) {
                        '-pem'      { RSA_Cryption_PEM }
                        '-der'      { RSA_Cryption_DER }
                    }
                }
                '-digital' {
                    switch ($rsa_format) {
                        '-pem'      { RSA_Digital_PEM }
                        '-der'      { RSA_Digital_DER }
                    }
                }
            }
        }
        default { Usage }
    }
    
    if ($operation -eq '-rs' -or $operation -eq '-ri') {
        break
    }
}

$endTime = [datetime]::UtcNow
$elapsedTime = ($endTime - $startTime).TotalSeconds
$formattedTime = "{0:F6}" -f $elapsedTime
Write-Host "Execution time: $formattedTime seconds"