![Project Banner](./AisIO.png)

# Manual

The repository contains binary file operations, Base encoding, and the use of encryption algorithms.

## Table of Contents
1. [Binary File Operations](#Binary-File-Operations)
2. [Base Text Encoding](#Base-Text-Encoding)
3. [AES Cryptography](#AES-Cryptography)
4. [DES Cryptography](#DES-Cryptography)
5. [HASH Calculation](#HASH-Calculation)

---

## **Binary File Operations**
Store your binary content, which can be used as sensitive data, identification number, replacement data, database storage, etc...

### Support Mode
1. Read (Binary File Read)
2. Write (Binary File Write)
3. Append (Binary File Append)
4. Insert (Binary File Insert)
5. Remove (Binary File Remove)
6. Indexes (Binary File Indexes)

### Support Type
1. Boolean
2. Unsigned Byte
3. Signed Byte
4. Signed Short Integer
5. Unsigned Short Integer
6. Signed Integer
7. Unsigned Integer
8. Signed Long Integer
9. Unsigned Long Integer
10. Single Floating Point
11. Double Floating Point
12. Bytes Array
13. String

### Binary Mode Introduction
| Mode      | Instruction                               | Use 
|-----------|-------------------------------------------|--------------------------------------------------------------------------
| Read      | `-r` `--read` `-rl` `--read-all`          | Read binary files, optional read all, read specific index, information.
| Write     | `-w` `--write`                            | Write content to a binary file. This action will force overwrite the original file.
| Append    | `-a` `--append`                           | Append content to the end of the binary file.
| Insert    | `-i` `--insert`                           | Insert content into a binary file, you can choose to insert the index, or insert the information.
| Remove    | `-rm` `--remove` `-rs` `--remove-index`   | Remove the contents of a binary file. You can choose to remove the index or remove the information.
| Indexes   | `-id` `--indexes`                         | Displays the index list of binary files, which can be used for reading, inserting, and removing.

### Binary Type Introduction
| Type Name             | Instruction   | Size (Bits)   | Size (Bytes)  | Data Range                                                | Use 
|-----------------------|---------------|---------------|---------------|-----------------------------------------------------------|--------------------------------------------------------------------------
| Boolean               | `-bool`       | 1             | 1             | `false` or `true`                                         | Used for binary states or flags.
| Unsigned Byte         | `-byte`       | 8             | 1             | `0` to `255`                                              | Stores small positive integers or raw byte data.
| Signed Byte           | `-sbyte`      | 8             | 1             | `-128` to `127`                                           | Stores small signed integers, often for encoded data.
| Signed Short Integer  | `-short`      | 16            | 2             | `-32768` to `32767`                                       | Common for small-range numeric data, such as sensor readings.
| Unsigned Short Integer| `-ushort`     | 16            | 2             | `0` to `65535`                                            | Stores unsigned integers like IDs or counts.
| Signed Integer        | `-int`        | 32            | 4             | `-2147483648` to `2147483647`                             | Used for standard numeric values, e.g., calculations or offsets.
| Unsigned Integer      | `-uint`       | 32            | 4             | `0` to `4294967295`                                       | Suitable for unsigned counters, memory sizes, or large IDs.
| Signed Long Integer   | `-long`       | 64            | 8             | `-9223372036854775808` to `9223372036854775807`           | Handles very large or small signed numbers, e.g., timestamps or high-precision counters.
| Unsigned Long Integer | `-ulong`      | 64            | 8             | `0` to `18446744073709551615`                             | Stores extremely large positive numbers, e.g., file sizes or cryptographic data.
| Single Floating Point | `-float`      | 32            | 4             | `~-3.402823e38` to `~3.402823e38`                         | Used for decimal values where precision is less critical, such as graphics or physics.
| Double Floating Point | `-double`     | 64            | 8             | `~-1.7976931348623157e308` to `~1.7976931348623157e308`   | Used for precise decimal numbers, like scientific calculations or financial data.
| Bytes Array           | `-bytes`      | N/A           | Variable      | N/A                                                       | Represents raw binary data, useful for encryption or file I/O.
| String                | `-string`     | N/A           | Variable      | N/A                                                       | Stores human-readable text or encoded binary data.

### Binary Notes:
1. **Boolean** : Represents a true/false state, common for flags or binary states.
2. **Floating-Point Types** : Ensure appropriate precision (`-float` for speed, `-double` for accuracy).
3. **Integer Types** : Select based on range and whether signed/unsigned is required.
4. **Bytes Array** : Essential for raw binary manipulation like file headers or encryption keys.
5. **String** : Ideal for readable text but may need encoding for certain applications.

### *Binary Instruction Usage*

#### *Binary example shell*
```sh
# Example Binary File Instructions
file="test.bin"

# Binary Read All
./aisio --read-all "$file"

# Binary Indexes
./aisio --indexes "$file"

# Binary Read
./aisio --read "$file" -bool -byte -sbyte -short -ushort -int -uint -long -ulong -float -double -bytes -string

# Binary Write
./aisio --write "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."

# Binary Append
./aisio --append "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."

# Binary Insert
./aisio --insert "$file" -bool true 0 -byte 255 0 -sbyte -128 0 -short 32767 0 -ushort 65535 0 -int 2147483647 0 -uint 4294967295 0 -long 9223372036854775807 0 -ulong 18446744073709551615 0 -float 3.1415927 0 -double 3.141592653589793 0 -bytes "This is Ais.IO Function Byte Array." 0 -string "This is Ais.IO Function String." 0

# Binary Remove
./aisio --remove "$file" -bool 0 1 -byte 2 1 -sbyte 4 2 -string 6 32

# Binary Remove Index
./aisio --remove-index "$file" 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50
```

---

## **Base Text Encoding**
Base text encoding involves converting binary data into textual representations.

### Support Mode
1. Base16 Encode/Decode
2. Base32 Encode/Decode
3. Base64 Encode/Decode
4. Base85 Encode/Decode

### Base Text Encoding Introduction
| Function  | Instruction       | Encode Length Formula     | Decode Length Formula | Use 
|-----------|-------------------|---------------------------|-----------------------|-----------------------------------------------------------------------------
| Base16    | `-b16` `--base16` | `n * 2 + 1`               | `n / 2`               | Encodes data as hexadecimal text, often used for debugging or checksums.
| Base32    | `-b32` `--base32` | `((n + 4) / 5) * 8 + 1`   | `(n / 8) * 5`         | Encodes data in a 32-character alphabet, commonly used in QR codes or URLs.
| Base64    | `-b64` `--base64` | `((n + 2) / 3) * 4 + 1`   | `(n / 4) * 3`         | Encodes binary data into ASCII text, widely used in data transmission, especially in emails and APIs.
| Base85    | `-b85` `--base85` | `((n + 3) / 4) * 5 + 1`   | `(n / 5) * 4`         | Encodes binary data efficiently into text, offering better compression compared to Base64.

### Formula Explanation

1. **Encode Length Formula**:
   - Calculates the length of encoded output based on input size `n`.
   - For example, encoding 10 bytes in Base64: `((10 + 2) / 3) * 4 = 16` characters.

2. **Decode Length Formula**:
   - Converts the encoded string length back to the original binary size.
   - For example, decoding a Base64 string of 16 characters: `(16 / 4) * 3 = 12` bytes.

### **Why is "+1" Needed in Encoding?**

1. **Base16 / Base32 / Base64 / Base85**:
   - The `+ 1` ensures room for padding characters or structural requirements (e.g., `=` in Base64).
   - Padding is used to make the encoded string length divisible by fixed blocks (Base64 uses blocks of 4).

2. **Example: Base64 Encoding**
   - Input size: 10 bytes
   - Formula: `((n + 2) / 3) * 4 + 1`
     - `(10 + 2) / 3 = 4` (round up to nearest integer)
     - Result: 16 characters (including padding).

3. **Impact of Padding on Decoding**:
   - When decoding, padding characters are ignored, restoring the original binary size.

### *Base Instruction Usage*

#### *Base example shell*
```sh
# Base16 Encode
./aisio --base16 -encode "This is Base16 Encode/Decode."

# Base16 Decode
./aisio --base16 -decode "546869732069732042617365313620456E636F64652F4465636F64652E"

# Base32 Encode
./aisio --base32 -encode "This is Base32 Encode/Decode."

# Base32 Decode
./aisio --base32 -decode "KRUGS4ZANFZSAQTBONSTGMRAIVXGG33EMUXUIZLDN5SGKLQ="

# Base64 Encode
./aisio --base64 -encode "This is Base64 Encode/Decode."

# Base64 Decode
./aisio --base64 -decode "VGhpcyBpcyBCYXNlNjQgRW5jb2RlL0RlY29kZS4="

# Base85 Encode
./aisio --base85 -encode "This is Base85 Encode/Decode."

# Base85 Decode
./aisio --base85 -decode 'RA^~)AZc?TLSb`dI5i+eZewp`WiLc!V{c?-E&u=k'
```
---

## **AES Cryptography**
AES (Advanced Encryption Standard) supports multiple encryption modes for secure communication.

### Aes Support Mode
1. CTR (Counter Mode)
2. CBC (Cipher Block Chaining)
3. CFB (Cipher Feedback)
4. OFB (Output Feedback)
5. ECB (Electronic Codebook)
6. GCM (Galois/Counter Mode)
7. CCM (Counter with CBC-MAC)
8. XTS (XEX-based Tweaked CodeBook Mode with CipherText Stealing)
9. OCB (Offset Codebook Mode)
10. WRAP (Key Wrap Mode)

### Aes Cryptography Introduction
| Mode  | Introduction  | Demand Introduction           | Use
|-------|---------------|-------------------------------|-------------------------------------------------------------------------
| CTR   | `-ctr`        | `-key` `-count`               | Suitable for encrypting streaming data, databases, and parallel processing.
| CBC   | `-cbc`        | `-key` `-iv` `-pad`           | Commonly used for encrypting files and bulk data with block chaining.
| CFB   | `-cfb`        | `-key` `-iv` `-seg`           | Ideal for real-time encryption, such as instant messaging or streaming data.
| OFB   | `-ofb`        | `-key` `-iv`                  | Useful for hardware or software stream encryption, such as radio or telephony.
| ECB   | `-ecb`        | `-key` `-pad`                 | Suitable for single block encryption, not recommended for multi-block data.
| GCM   | `-gcm`        | `-key` `-nonce` `-tag` `-aad` | Preferred for secure data transmission, offering encryption and integrity checking.
| CCM   | `-ccm`        | `-key` `-nonce` `-tag` `-aad` | Suitable for embedded systems and low-power devices requiring integrity protection.
| XTS   | `-xts`        | `-key` `-key2` `-tweak`       | Best choice for disk or storage encryption to avoid sector duplication issues.
| OCB   | `-ocb`        | `-key` `-nonce` `-tag` `-aad` | Provides high-performance encryption with integrated integrity protection.
| WRAP  | `-wrap`       | `-key` `-kek` `-wrapkey`      | Designed for secure key management and wrapping sensitive keys for storage.

### Aes Ranking
| Mode  | Safety (40%)  | Complex (30%) | Widely (30%)  | Score (1~10)  | Reason
|-------|---------------|---------------|---------------|---------------|-------------------------------------------------
| GCM   | 10            | 8             | 10            | 9.4           | Efficient, secure, and widely used in modern encrypted transmission protocols (such as TLS, IPSec).
| OCB   | 10            | 7             | 6             | 8.0           | It has extremely high security and excellent performance, but its application scope is limited due to patent restrictions.
| CCM   | 9             | 7             | 7             | 7.9           | Provides integrity protection and is suitable for embedded and low-power devices, but is slightly less efficient than GCM.
| XTS   | 8             | 6             | 8             | 7.6           | The best choice for storage encryption, designed to solve the problem of disk and sector duplication, and widely used in disk encryption systems.
| WRAP  | 9             | 6             | 7             | 7.7           | A mode dedicated to key protection, with high security but narrow application scope.
| CTR   | 8             | 9             | 9             | 8.5           | Efficient and easy to implement, suitable for stream data encryption, but lacks integrity protection.
| CBC   | 7             | 7             | 8             | 7.5           | Traditional mode, suitable for old systems, but vulnerable to padding attacks.
| CFB   | 6             | 8             | 6             | 6.9           | Suitable for streaming data encryption, but gradually replaced by more efficient modes.
| OFB   | 6             | 8             | 5             | 6.5           | Similar to CTR, but lacks built-in integrity protection and has limited applications.
| ECB   | 3             | 10            | 2             | 5.2           | Simple and efficient, but extremely unsafe, not recommended.

### *Aes Scoring formula*
 - Total score = (Security × 40%) + (Complexity × 30%) + (Broadness × 30%)
 - Security : Evaluated based on resistance to attacks, integrity protection and uniqueness requirements.
 - Complexity : Consider the difficulty, efficiency, and user-friendliness of implementation.
 - Extensiveness : Based on current technical standards and actual application frequency.

### *Aes Instruction Usage*

#### *Aes example shell*
```sh
# Example Aes Instructions
# Aes Settings...
AES_KEY="Key length must be 128, 192, 256"
AES_IV="IvMustBe128Size."
AES_NONCE="Nonce12bytes"
AES_TAG="TagMustBe128Size"
AES_AAD="Additional Authenticated Data (AAD) can be of any length"
AES_KEY2="Secondary Key for AES-XTS Tweak."
AES_TWEAK="SectorNumber0001"
AES_COUNTER=1
AES_GCM_TAG="73DD32019CD29E7251D17128DE27FFDD"
AES_CCM_TAG="DB9A881B8A159B079F826BD043A4F8C9"
AES_OCB_TAG="F7F64A75E6575C9093E12AB272CBF024"
AES_KEK="This is AES WRAP, 128, 192, 256."
BASE="-base16"

# AES CTR Encryption/Decryption
./aisio --aes -ctr -encrypt -key "$AES_KEY" -counter "$AES_COUNTER" -plain-text "This is AES CTR Encryption/Decryption." -out "$BASE"
./aisio --aes -ctr -decrypt -key "$AES_KEY" -counter "$AES_COUNTER" -cipher-text "$BASE" "7F603AB98AF7073B205309B91FCAFC9581DD36055EB25C533429C9EB0C41ACF5070FA94FD62A"

# AES CBC Encryption/Decryption
./aisio --aes -cbc -encrypt -key "$AES_KEY" -iv "$AES_IV" -padding -plain-text "This is AES CBC Encryption/Decryption." -out "$BASE"
./aisio --aes -cbc -decrypt -key "$AES_KEY" -iv "$AES_IV" -padding -cipher-text "$BASE" "FAFEF277E6AF54441F3407175D3860D16BEDC9570CBB83F9609E2CE90AB1596D02167AA72C5A199D7810C0D0FEC674F8"

# AES CFB Encryption/Decryption
./aisio --aes -cfb -encrypt -key "$AES_KEY" -iv "$AES_IV" -segment 128 -plain-text "This is AES CFB Encryption/Decryption." -out "$BASE"
./aisio --aes -cfb -decrypt -key "$AES_KEY" -iv "$AES_IV" -segment 128 -cipher-text "$BASE" "8A30BF00B0F15E4616BF4C9B5742591D658641BE4CE31B24041FA41B791F3021531F171CD401"

# AES OFB Encryption/Decryption
./aisio --aes -ofb -encrypt -key "$AES_KEY" -iv "$AES_IV" -plain-text "This is AES OFB Encryption/Decryption." -out "$BASE"
./aisio --aes -ofb -decrypt -key "$AES_KEY" -iv "$AES_IV" -cipher-text "$BASE" "8A30BF00B0F15E4616BF4C9B5B42591DCF29C1A2F23F43E35CB140041964E890070AAC2913E0"

# AES ECB Encryption/Decryption
./aisio --aes -ecb -encrypt -key "$AES_KEY" -padding -plain-text "This is AES ECB Encryption/Decryption." -out "$BASE"
./aisio --aes -ecb -decrypt -key "$AES_KEY" -padding -cipher-text "$BASE" "1CD7A6E38BDBDD9F1EFE4BA5A17AB72CDB9CE185F374FBA7DC7C839C5AC30F7CC070E0DD9FA85879BCF8C8049E637406"

# AES GCM Encryption/Decryption
./aisio --aes -gcm -encrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$AES_TAG" -aad "$AES_AAD" -plain-text "This is AES GCM Encryption/Decryption." -out "$BASE"
./aisio --aes -gcm -decrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$BASE" "$AES_GCM_TAG" -aad "$AES_AAD" -cipher-text "$BASE" "742389440288A533843D6156F6CC67C28C543B1F397734BA01BE7173FC3E486B70E7A4CD2DF0"

# AES CCM Encryption/Decryption
./aisio --aes -ccm -encrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$AES_TAG" -aad "$AES_AAD" -plain-text "This is AES CCM Encryption/Decryption." -out "$BASE"
./aisio --aes -ccm -decrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$BASE" "$AES_CCM_TAG" -aad "$AES_AAD" -cipher-text "$BASE" "5245E1C1520D7BC2E1530310E52BA74D96D1C97A8BE395AF88EEFF71D44BEC2EFEF8F6B65761"

# AES XTS Encryption/Decryption
./aisio --aes -xts -encrypt -key "$AES_KEY" -key2 "$AES_KEY2" -tweak "$AES_TWEAK" -plain-text "This is AES XTS Encryption/Decryption." -out "$BASE"
./aisio --aes -xts -decrypt -key "$AES_KEY" -key2 "$AES_KEY2" -tweak "$AES_TWEAK" -cipher-text "$BASE" "2BC71BB83EEA376368F9429D09470359293905826B14EDA8B170C3E7A4958020C6AF061181B4"

# AES OCB Encryption/Decryption
./aisio --aes -ocb -encrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$AES_TAG" -aad "$AES_AAD" -plain-text "This is AES OCB Encryption/Decryption." -out "$BASE"
./aisio --aes -ocb -decrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$BASE" "$AES_OCB_TAG" -aad "$AES_AAD" -cipher-text "$BASE" "3F405A527F7E26DAA3DB8F55D32D33A63C48A9ED40E0ED410CD9E8FC3E090B9627FCC10355A3"

# AES WRAP Encryption/Decryption
./aisio --aes -wrap -encrypt -key "$AES_KEY" -kek "$AES_KEK" -out "$BASE"
./aisio --aes -wrap -decrypt -wrapkey "$BASE" "4A0953B24807510E39F18A1AF98153FBA9BF306092D15BB4FB75A04A95148C25B99D7F3A5589FD26" -kek "$AES_KEK"
```

---

## **DES Cryptography**
DES (Data Encryption Standard) is used for secure communication in legacy systems.

### Support Mode
1. CBC (Cipher Block Chaining)
2. CFB (Cipher Feedback)
3. OFB (Output Feedback)
4. ECB (Electronic Codebook)
5. WRAP (Key Wrap Mode)

### Des Cryptography Introduction
| Mode  | Introduction  | Demand Introduction           | Use
|-------|---------------|-------------------------------|-------------------------------------------------------------------------
| CBC   | `-cbc`        | `-key` `-iv` `-pad`           | Commonly used for file encryption or block data encryption in legacy systems.
| CFB   | `-cfb`        | `-key` `-iv` `-seg`           | Suitable for streaming data encryption, such as real-time communication systems.
| OFB   | `-ofb`        | `-key` `-iv`                  | Often used in telecommunication or hardware encryption where stream mode is needed.
| ECB   | `-ecb`        | `-key` `-pad`                 | Limited to single block encryption, not recommended for general use due to low security.
| WRAP  | `-wrap`       | `-key` `-kek` `-wrapkey`      | Used for key wrapping and management, ensuring secure storage or transfer of keys.

### Ranking
| Mode  | Safety (40%)  | Complex (30%) | Widely (30%)  | Score (1~10)  | Reason
|-------|---------------|---------------|---------------|---------------|----------------------------------------------------------------
| WRAP  | 6             | 6             | 5             | 5.7           | Dedicated to key management, it has high security, but its application scope is narrow and its 3DES encryption performance is low.
| CBC   | 5             | 6             | 6             | 5.6           | A common pattern in legacy systems, suitable for block encryption, but security is limited by IV management and the risk of padding attacks.
| CFB   | 4             | 6             | 4             | 4.6           | Stream encryption mode is suitable for old instant messaging. It has insufficient security and relatively poor performance, and its application is gradually decreasing.
| OFB   | 4             | 6             | 3             | 4.3           | Similar to CFB, but with a simpler mode, narrower application, and no integrity protection.
| ECB   | 2             | 8             | 2             | 3.4           | Simple and efficient, but extremely insecure, it is only suitable for special scenarios without sensitive data (such as data alignment testing).

### *Des Scoring formula*
 - Total score = (Security × 40%) + (Complexity × 30%) + (Broadness × 30%)
 - Security : Evaluated based on resistance to attacks, integrity protection and uniqueness requirements.
 - Complexity : Consider the difficulty, efficiency, and user-friendliness of implementation.
 - Extensiveness : Based on current technical standards and actual application frequency.

### *Des Instruction Usage*

#### *Des example shell*
```sh
# Example Des Instructions
# Des Settings...
DES_KEY="Key Must Be 128,192 Size"
DES_IV="Iv8Bytes"
DES_KEK="WRAP Key 128 192 by DES."
BASE="-base16"

# DES CBC Encryption/Decryption
./aisio -des -cbc -encrypt -key "$DES_KEY" -iv "$DES_IV" -padding -plain-text "This is DES CBC Encryption/Decryption." -out "$BASE"
./aisio -des -cbc -decrypt -key "$DES_KEY" -iv "$DES_IV" -padding -cipher-text "$BASE" "D53DB3162D7E9A594C574BD6BFE734EBFE30DF7625F68AAD45932111EE6E421FA19624C47AE22DCF"

# DES CFB Encryption/Decryption
./aisio -des -cfb -encrypt -key "$DES_KEY" -iv "$DES_IV" -segment 128 -plain-text "This is DES CFB Encryption/Decryption." -out "$BASE"
./aisio -des -cfb -decrypt -key "$DES_KEY" -iv "$DES_IV" -segment 128 -cipher-text $BASE "479A7330CE6D3098CA0FD5A2569AB8C9A2D8C5BAC89A7273C28AC546F187007DC010D6FBFE00"

# DES OFB Encryption/Decryption
./aisio -des -ofb -encrypt -key "$DES_KEY" -iv "$DES_IV" -plain-text "This is DES OFB Encryption/Decryption." -out "$BASE"
./aisio -des -ofb -decrypt -key "$DES_KEY" -iv "$DES_IV" -cipher-text "$BASE" "479A7330CE6D3098F01B383128162351EDD36481B3A3364FF992EA0B491FCD420B2A24C1DC19"

# DES ECB Encryption/Decryption
./aisio -des -ecb -encrypt -key "$DES_KEY" -padding -plain-text "This is DES ECB Encryption/Decryption." -out "$BASE"
./aisio -des -ecb -decrypt -key "$DES_KEY" -padding -cipher-text "$BASE" "8F10D1E43B42177E6EB26786CAC82B3A2E677A1B59AB8CD5C283E7605F4F42E957D594E8885EF5B1"

# DES WRAP Encryption/Decryption
./aisio -des -wrap -encrypt -key "$DES_KEY" -kek "$DES_KEK" -out "$BASE"
./aisio -des -wrap -decrypt -wrapkey "$BASE" "F033669ADDDD49C08A5D3BEE5198897D97F6B4E14644E30547CE756961857C28E437634A8D4A1C0B" -kek "$DES_KEK"
```

---

## **HASH Calculation**
Hash functions provide data integrity by generating fixed-length digests.

### Support Mode
1. MD5
2. MD5_SHA1
3. SHA1
4. SHA2_224
5. SHA2_256
6. SHA2_384
7. SHA2_512
8. SHA2_512_224
9. SHA2_512_256
10. SHA3_224
11. SHA3_256
12. SHA3_384
13. SHA3_512
14. SHA3_KE_128
15. SHA3_KE_256
16. BLAKE2S_256
17. BLAKE2B_512
18. SM3
19. RIPEMD160

### Hash Calculation Introduction
| Hash Type     | Introduction      | Variable Introduction                 | Use
|---------------|-------------------|---------------------------------------|------------------------------------------------------------
| MD5           | `-md5`            | `-salt` `-fir` `-mid` `-las`          | Used for non-secure checksum calculations or quick data integrity checks.
| MD5-SHA1      | `-md5-sha1`       | `-salt` `-fir` `-mid` `-las`          | Combines MD5 and SHA1 for legacy TLS 1.2 applications, but not recommended anymore.
| SHA1          | `-sha1`           | `-salt` `-fir` `-mid` `-las`          | Deprecated but still used for legacy systems or low-security requirements.
| SHA2-224      | `-sha2-224`       | `-salt` `-fir` `-mid` `-las`          | Suitable for lightweight applications in embedded systems or IoT devices.
| SHA2-256      | `-sha2-256`       | `-salt` `-fir` `-mid` `-las`          | Industry-standard hash for digital signatures, certificates, and general security.
| SHA2-384      | `-sha2-384`       | `-salt` `-fir` `-mid` `-las`          | Provides additional security for sensitive applications like blockchain or finance.
| SHA2-512      | `-sha2-512`       | `-salt` `-fir` `-mid` `-las`          | Suitable for high-security requirements, but slower than SHA2-256.
| SHA2-512-224  | `-sha2-512-224`   | `-salt` `-fir` `-mid` `-las`          | Truncated version of SHA2-512, ideal for resource-constrained environments.
| SHA2-512-256  | `-sha2-512-256`   | `-salt` `-fir` `-mid` `-las`          | Truncated SHA2-512 variant, balancing security and performance.
| SHA3-224      | `-sha3-224`       | `-salt` `-fir` `-mid` `-las`          | Lightweight and secure, suitable for IoT or compact applications.
| SHA3-256      | `-sha3-256`       | `-salt` `-fir` `-mid` `-las`          | High-security applications like cryptographic signatures and secure protocols.
| SHA3-384      | `-sha3-384`       | `-salt` `-fir` `-mid` `-las`          | Used in scenarios requiring stronger security than SHA3-256, but with larger output.
| SHA3-512      | `-sha3-512`       | `-salt` `-fir` `-mid` `-las`          | Maximum security applications, often used in cryptography or digital certificates.
| SHA3-KE-128   | `-sha3-ke-128`    | `-salt` `-fir` `-mid` `-las` `-len`   | Variable-length output for specific cryptographic tasks requiring 128-bit security.
| SHA3-KE-256   | `-sha3-ke-256`    | `-salt` `-fir` `-mid` `-las` `-len`   | Variable-length output for flexible cryptographic needs with higher security.
| BLAKE2S-256   | `-blake2s-256`    | `-salt` `-fir` `-mid` `-las`          | Efficient for constrained environments like IoT or small devices.
| BLAKE2B-512   | `-blake2b-512`    | `-salt` `-fir` `-mid` `-las`          | High-efficiency hashing for large-scale applications or high-security needs.
| SM3           | `-sm3`            | `-salt` `-fir` `-mid` `-las`          | Cryptographic hash standard in China, suitable for regulatory compliance.
| RIPEMD160     | `-sm3`            | `-salt` `-fir` `-mid` `-las`          | Used in specific scenarios like Bitcoin addresses, limited in modern applications.

### Ranking
| Hash Type         | Safety (40%)  | Complex (30%) | Widely (30%)  | Score (1~10)  | Reason
|-------------------|---------------|---------------|---------------|---------------|-------------------------------------------------------------------------
| SHA3-256          | 10            | 8             | 9             | 9.1           | It has high security, strong anti-collision ability, and gradually increases in popularity, making it suitable for cryptographic applications and scenarios with high security requirements.
| SHA2-256          | 9             | 8             | 10            | 9.0           | Industry standard, widely used, strong anti-attack capability, suitable for most application scenarios.
| BLAKE2B-512       | 9             | 9             | 8             | 8.9           | Efficient and safe, supports configurable length output, suitable for performance-sensitive applications, and second only to the SHA series in popularity.
| SHA3-512          | 10            | 7             | 7             | 8.7           | Provides the highest security, but is not as widely used as SHA2.
| SHA2-512          | 9             | 8             | 8             | 8.7           | It is suitable for scenarios with high security requirements, such as digital signatures and blockchain, but its computational efficiency is slightly lower.
| SHA3-384          | 10            | 7             | 6             | 8.5           | High security, suitable for scenarios that require higher security, but its application popularity is limited.
| SHA2-384          | 9             | 7             | 7             | 8.2           | Suitable for applications with medium to high security requirements. It has a higher computational cost and is less popular than SHA2-256.
| SHA3-224          | 9             | 8             | 6             | 8.0           | It is suitable for scenarios that require lightweight and high security, and has great potential for future applications.
| SHA2-224          | 8             | 8             | 7             | 7.9           | The choice for lightweight security requirements, suitable for embedded applications.
| BLAKE2S-256       | 8             | 9             | 6             | 7.9           | It is efficient and lightweight, suitable for scenarios with limited resources, such as IoT devices, but its application popularity is slightly lower.
| SM3               | 8             | 7             | 7             | 7.8           | It is suitable for Chinese cryptographic standard scenarios. Its collision resistance and security are not as good as SHA3, but it has advantages in specific applications.
| RIPEMD160         | 7             | 8             | 7             | 7.5           | Used in specific scenarios such as Bitcoin address generation, with limited security and popularity and moderate performance.
| SHA3-KE-256       | 9             | 8             | 5             | 7.5           | Variable output length, suitable for flexible scenarios, high security, but relatively low popularity.
| SHA3-KE-128       | 8             | 8             | 5             | 7.3           | Variable output length, suitable for flexible scenarios, but less secure and popular than SHA3-KE-256.
| SHA2-512-256      | 9             | 7             | 6             | 7.3           | A truncated version of SHA-512, suitable for scenarios that require a fixed output length and medium to high security.
| SHA2-512-224      | 8             | 7             | 6             | 7.1           | A truncated version of SHA-512 that has similar applications to SHA2-224, but is less commonly used in real-world applications.
| SHA1              | 5             | 8             | 6             | 6.2           | It is considered unsafe but still has legacy applications in old systems suitable for low security requirements.
| MD5-SHA1          | 5             | 9             | 5             | 6.0           | Related to legacy applications in TLS 1.2, but not as secure.
| MD5               | 3             | 9             | 6             | 5.4           | Fast but completely insecure, only suitable for non-security verification scenarios.

### *Scoring formula*
 - Total score = (Security × 40%) + (Complexity × 30%) + (Broadness × 30%)
 - Security : Evaluated based on resistance to attacks, integrity protection and uniqueness requirements.
 - Complexity : Consider the difficulty, efficiency, and user-friendliness of implementation.
 - Extensiveness : Based on current technical standards and actual application frequency.


### *Hash Instruction Usage*

#### *Hash example shell*
```sh
BASE="-base16"

# HASH MD5
./aisio -hash -md5 -in "This is HASH-MD5 by the Hash libary." -salt "This is HASH-MD5 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH MD5-SHA1
./aisio -hash -md5-sha1 -in "This is HASH-MD5-SHA1 by the Hash libary." -salt "This is HASH-MD5-SHA1 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA1
./aisio -hash -sha1 -in "This is HASH-SHA1 by the Hash libary." -salt "This is HASH-SHA1 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA2-224
./aisio -hash -sha2-224 -in "This is HASH-SHA2-224 by the Hash libary." -salt "This is HASH-SHA2-224 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA2-256
./aisio -hash -sha2-256 -in "This is HASH-SHA2-256 by the Hash libary." -salt "This is HASH-SHA2-256 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA2-384
./aisio -hash -sha2-384 -in "This is HASH-SHA2-384 by the Hash libary." -salt "This is HASH-SHA2-384 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA2-512
./aisio -hash -sha2-512 -in "This is HASH-SHA2-512 by the Hash libary." -salt "This is HASH-SHA2-512 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA2-512-224
./aisio -hash -sha2-512-224 -in "This is HASH-SHA2-512-224 by the Hash libary." -salt "This is HASH-SHA2-512-224 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA2-512-256
./aisio -hash -sha2-512-256 -in "This is HASH-SHA2-512-256 by the Hash libary." -salt "This is HASH-SHA2-512-256 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA3-224
./aisio -hash -sha3-224 -in "This is HASH-SHA3-224 by the Hash libary." -salt "This is HASH-SHA3-224 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA3-256
./aisio -hash -sha3-256 -in "This is HASH-SHA3-256 by the Hash libary." -salt "This is HASH-SHA3-256 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA3-384
./aisio -hash -sha3-384 -in "This is HASH-SHA3-384 by the Hash libary." -salt "This is HASH-SHA3-384 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA3-512
./aisio -hash -sha3-512 -in "This is HASH-SHA3-512 by the Hash libary." -salt "This is HASH-SHA3-512 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SHA3-KE-128
./aisio -hash -sha3-ke-128 -in "This is HASH-SHA3-KE-128 by the Hash libary." -salt "This is HASH-SHA3-KE-128 Salt by the Hash." -length 16 -fir -mid -las -out "$BASE"

# HASH SHA3-KE-256
./aisio -hash -sha3-ke-256 -in "This is HASH-SHA3-KE-256 by the Hash libary." -salt "This is HASH-SHA3-KE-256 Salt by the Hash." -length 32 -fir -mid -las -out "$BASE"

# HASH BLAKE2S-256
./aisio -hash -blake2s-256 -in "This is HASH-BLAKE2S-256 by the Hash libary." -salt "This is HASH-BLAKE2S-256 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH BLAKE2B-512
./aisio -hash -blake2b-512 -in "This is HASH-BLAKE2B-512 by the Hash libary." -salt "This is HASH-BLAKE2B-512 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH SM3
./aisio -hash -sm3 -in "This is HASH-SM3 by the Hash libary." -salt "This is HASH-SM3 Salt by the Hash." -fir -mid -las -out "$BASE"

# HASH RIPEMD160
./aisio -hash -sm3 -in "This is HASH-SM3 by the Hash libary." -salt "This is HASH-RIPEMD160 Salt by the Hash." -fir -mid -las -out "$BASE"
```

---
