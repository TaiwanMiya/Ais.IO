![Project Banner](./AisIO.png)

# Manual

The repository contains binary file operations, Base encoding, and the use of encryption algorithms.

## Table of Contents
1. [Binary File Operations](#Binary-File-Operations)
2. [Base Text Encoding](#Base-Text-Encoding)
3. [AES Cryptography](#AES-Cryptography)
4. [DES Cryptography](#DES-Cryptography)
5. [HASH Calculation](#HASH-Calculation)
6. [RSA Cryptography](#RSA-Cryptography)
7. [Ais IO License](#License)

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
| Mode          | Instruction                                            | Use 
|---------------|--------------------------------------------------------|--------------------------------------------------------------------------
| **`Read`**    | `-r` `--read` `-rl` `--read-all` `-ri` `--read-index`  | Read binary files, optional read all, read specific index, information etc...
| **`Write`**   | `-w` `--write`                                         | Write content to a binary file. This action will force overwrite the original file.
| **`Append`**  | `-a` `--append`                                        | Append content to the end of the binary file.
| **`Insert`**  | `-i` `--insert`                                        | Insert content into a binary file, you can choose to insert the index, or insert the information.
| **`Remove`**  | `-rm` `--remove` `-rs` `--remove-index`                | Remove the contents of a binary file. You can choose to remove the index or remove the information.
| **`Indexes`** | `-id` `--indexes`                                      | Displays the index list of binary files, which can be used for reading, inserting, and removing.

### Binary Type Introduction
| Type Name                    | Instruction   | Size (Bits)   | Size (Bytes)  | Data Range                                                | Use 
|------------------------------|---------------|---------------|---------------|-----------------------------------------------------------|--------------------------------------------------------------------------
| **`Boolean`**                | `-bool`       | 1             | 1             | `false` or `true`                                         | Used for binary states or flags.
| **`Unsigned Byte`**          | `-byte`       | 8             | 1             | `0` to `255`                                              | Stores small positive integers or raw byte data.
| **`Signed Byte`**            | `-sbyte`      | 8             | 1             | `-128` to `127`                                           | Stores small signed integers, often for encoded data.
| **`Signed Short Integer`**   | `-short`      | 16            | 2             | `-32768` to `32767`                                       | Common for small-range numeric data, such as sensor readings.
| **`Unsigned Short Integer`** | `-ushort`     | 16            | 2             | `0` to `65535`                                            | Stores unsigned integers like IDs or counts.
| **`Signed Integer`**         | `-int`        | 32            | 4             | `-2147483648` to `2147483647`                             | Used for standard numeric values, e.g., calculations or offsets.
| **`Unsigned Integer`**       | `-uint`       | 32            | 4             | `0` to `4294967295`                                       | Suitable for unsigned counters, memory sizes, or large IDs.
| **`Signed Long Integer`**    | `-long`       | 64            | 8             | `-9223372036854775808` to `9223372036854775807`           | Handles very large or small signed numbers, e.g., timestamps or high-precision counters.
| **`Unsigned Long Integer`**  | `-ulong`      | 64            | 8             | `0` to `18446744073709551615`                             | Stores extremely large positive numbers, e.g., file sizes or cryptographic data.
| **`Single Floating Point`**  | `-float`      | 32            | 4             | `~-3.402823e38` to `~3.402823e38`                         | Used for decimal values where precision is less critical, such as graphics or physics.
| **`Double Floating Point`**  | `-double`     | 64            | 8             | `~-1.7976931348623157e308` to `~1.7976931348623157e308`   | Used for precise decimal numbers, like scientific calculations or financial data.
| **`Bytes Array`**            | `-bytes`      | N/A           | Variable      | N/A                                                       | Represents raw binary data, useful for encryption or file I/O.
| **`String`**                 | `-string`     | N/A           | Variable      | N/A                                                       | Stores human-readable text or encoded binary data.

### Binary Notes:
1. **Boolean** : Represents a true/false state, common for flags or binary states.
2. **Floating-Point Types** : Ensure appropriate precision (`-float` for speed, `-double` for accuracy).
3. **Integer Types** : Select based on range and whether signed/unsigned is required.
4. **Bytes Array** : Essential for raw binary manipulation like file headers or encryption keys.
5. **String** : Ideal for readable text but may need encoding for certain applications.

### *Binary Instruction Usage*

#### *Binary example shell*
```sh
#!/bin/bash
# Example Binary File Instructions
# Binary Settings...
file="test.bin"
BASE="-base16"

# Binary Write
./aisio --write "$BASE" "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "0123456789ABCDEF0123456789ABCDEF" -string "This is Ais.IO Function String."

# Binary Append
./aisio --append "$BASE" "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "0123456789ABCDEF0123456789ABCDEF" -string "This is Ais.IO Function String."

# Binary Insert
./aisio --insert "$BASE" "$file" -bool true 0 -byte 255 0 -sbyte -128 0 -short 32767 0 -ushort 65535 0 -int 2147483647 0 -uint 4294967295 0 -long 9223372036854775807 0 -ulong 18446744073709551615 0 -float 3.1415927 0 -double 3.141592653589793 0 -bytes "0123456789ABCDEF0123456789ABCDEF" 0 -string "This is Ais.IO Function String." 0

# Binary Remove
./aisio --remove "$file" -bool 118 1 -byte 116 1 -sbyte 114 1 -short 111 2 -ushort 108 2 -int 103 4 -uint 98 4 -long 89 8 -ulong 80 8 -float 75 4 -double 66 8 -bytes 41 16 -string 0 32

# Binary Remove Index
./aisio --remove-index "$file" 0 2 5~7 4*2 1+7*3

# Binary Indexes
./aisio --indexes "$file"

# Binary Read
./aisio --read "$BASE" "$file" -short -float -double -bytes -string -bool -byte -short -ushort -int -uint -long -ulong -float -double -bytes -string

# Binary Read Index
./aisio --read-index "$BASE" "$file" 4 1~3 5*2 0+6*2

# Binary Read All
./aisio --read-all "$BASE" "$file"
```

---

## **Base Text Encoding**
Base text encoding involves converting binary data into textual representations.

### Support Mode
1. Base10 Encode/Decode
2. Base16 Encode/Decode
3. Base32 Encode/Decode
4. Base58 Encode/Decode
5. Base62 Encode/Decode
6. Base64 Encode/Decode
7. Base85 Encode/Decode
8. Base91 Encode/Decode

### Base Text Encoding Introduction
| Function     | Instruction       | Encode Length Formula     | Decode Length Formula | Use 
|--------------|-------------------|---------------------------|-----------------------|-----------------------------------------------------------------------------
| **`Base10`** | `-b10` `--base10` | `n * 2.56 + 1`            | `m / 2.56`            | This encoding is commonly used for BigInt (arbitrary-precision integers).
| **`Base16`** | `-b16` `--base16` | `n * 2 + 1`               | `m / 2`               | Encodes data as hexadecimal text, often used for debugging or checksums.
| **`Base32`** | `-b32` `--base32` | `((n + 4) / 5) * 8 + 1`   | `(m / 8) * 5`         | Encodes data in a 32-character alphabet, commonly used in QR codes or URLs.
| **`Base58`** | `-b58` `--base58` | `n * 8 / 5.8 + 1`         | `m * 5.8 / 8`         | Base58 encoding is used primarily in Bitcoin, URL shorteners, file storage systems and other cryptocurrencies.
| **`Base62`** | `-b62` `--base62` | `n * 8 / 6.2 + 1`         | `m * 6.2 / 8`         | Base62 encoding is often used for URLs, unique identifiers, and short links.
| **`Base64`** | `-b64` `--base64` | `((n + 2) / 3) * 4 + 1`   | `(m / 4) * 3`         | Encodes binary data into ASCII text, widely used in data transmission, especially in emails and APIs.
| **`Base85`** | `-b85` `--base85` | `((n + 3) / 4) * 5 + 1`   | `(m / 5) * 4`         | Encodes binary data efficiently into text, offering better compression compared to Base64.
| **`Base91`** | `-b91` `--base91` | `n * 8 / 9.1 + 1`         | `m * 9.1 / 8`         | Base91 is often used in binary-to-text encoding applications where maximizing space savings is crucial.

### Base Encoder Ranking
| Encoding     | Safety (15%) | Complexity (10%) | Widely (20%) | Recognizability (20%) | Usability (15%) | Speed (20%) | Score (1~10) |
|--------------|--------------|------------------|--------------|-----------------------|-----------------|-------------|--------------|
| **`Base16`** | 6            | 5                | 10           | 10                    | 10              | 9           | *`8.3`*      |
| **`Base64`** | 7            | 6                | 10           | 6                     | 9               | 9           | *`7.6`*      |
| **`Base32`** | 7            | 6                | 7            | 6                     | 8               | 9           | *`6.8`*      |
| **`Base62`** | 8            | 7                | 8            | 7                     | 8               | 4           | *`6.7`*      |
| **`Base58`** | 8            | 7                | 7            | 7                     | 8               | 4           | *`6.5`*      |
| **`Base91`** | 8            | 7                | 5            | 6                     | 6               | 9           | *`6.4`*      |
| **`Base85`** | 7            | 6                | 4            | 6                     | 6               | 9           | *`5.9`*      |
| **`Base10`** | 5            | 4                | 3            | 5                     | 5               | 2           | *`3.8`*      |

### *Base Encoder Scoring formula*
 - Total score = (Security × 15%) + (Complexity × 10%) + (Broadness × 20%) + (Recognizability x 20%) + (Usability x 15%) + (Speed x 20%)
 - Security : Evaluated based on resistance to attacks, integrity protection and uniqueness requirements.
 - Complexity : Consider the difficulty, efficiency, and user-friendliness of implementation.
 - Extensiveness : Based on current technical standards and actual application frequency.
 - Recognizability : The score is based on whether the encoded result is easy for humans to recognize.
 - Usability : Consider ease of user operation and ubiquity of tool support.
 - Speed : Consider the speed of encoding and decoding, including internal logic issues.

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
#!/bin/bash
# Base10 Encode
./aisio --base10 -encode "This is Base10 Encode/Decode."

# Base10 Decode
./aisio --base10 -decode "2275631377870141336533466315340532913972637215315185916509608405656878"

# Base16 Encode
./aisio --base16 -encode "This is Base16 Encode/Decode."

# Base16 Decode
./aisio --base16 -decode "546869732069732042617365313620456E636F64652F4465636F64652E"

# Base32 Encode
./aisio --base32 -encode "This is Base32 Encode/Decode."

# Base32 Decode
./aisio --base32 -decode "KRUGS4ZANFZSAQTBONSTGMRAIVXGG33EMUXUIZLDN5SGKLQ="

# Base58 Encode
./aisio --base58 -encode "This is Base58 Encode/Decode."

# Base58 Decode
./aisio --base58 -decode "4qFPnPkVdmicitJgEZS1kVZHMXD55q1CmJ6MssHP"

# Base62 Encode
./aisio --base62 -encode "This is Base62 Encode/Decode."

# Base62 Decode
./aisio --base62 -decode "HcyJuDO7FzrCwYNWtbLv0nkZbFlzeZg5gRAMIYQ"

# Base64 Encode
./aisio --base64 -encode "This is Base64 Encode/Decode."

# Base64 Decode
./aisio --base64 -decode "VGhpcyBpcyBCYXNlNjQgRW5jb2RlL0RlY29kZS4="

# Base85 Encode
./aisio --base85 -encode "This is Base85 Encode/Decode."

# Base85 Decode
./aisio --base85 -decode 'RA^~)AZc?TLSb`dI5i+eZewp`WiLc!V{c?-E&u=k'

# Base91 Encode
./aisio --base91 -encode "This is Base91 Encode/Decode."

# Base91 Decode
./aisio --base91 -decode 'nX,<:WRT$F,ue9QUz\"y+|irMn<{vJT1T20DC'
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
| Mode       | Introduction  | Demand Introduction           | Use
|------------|---------------|-------------------------------|-------------------------------------------------------------------------
| **`CTR`**  | `-ctr`        | `-key` `-count`               | Suitable for encrypting streaming data, databases, and parallel processing.
| **`CBC`**  | `-cbc`        | `-key` `-iv` `-pad`           | Commonly used for encrypting files and bulk data with block chaining.
| **`CFB`**  | `-cfb`        | `-key` `-iv` `-seg`           | Ideal for real-time encryption, such as instant messaging or streaming data.
| **`OFB`**  | `-ofb`        | `-key` `-iv`                  | Useful for hardware or software stream encryption, such as radio or telephony.
| **`ECB`**  | `-ecb`        | `-key` `-pad`                 | Suitable for single block encryption, not recommended for multi-block data.
| **`GCM`**  | `-gcm`        | `-key` `-nonce` `-tag` `-aad` | Preferred for secure data transmission, offering encryption and integrity checking.
| **`CCM`**  | `-ccm`        | `-key` `-nonce` `-tag` `-aad` | Suitable for embedded systems and low-power devices requiring integrity protection.
| **`XTS`**  | `-xts`        | `-key` `-key2` `-tweak`       | Best choice for disk or storage encryption to avoid sector duplication issues.
| **`OCB`**  | `-ocb`        | `-key` `-nonce` `-tag` `-aad` | Provides high-performance encryption with integrated integrity protection.
| **`WRAP`** | `-wrap`       | `-key` `-kek` `-wrapkey`      | Designed for secure key management and wrapping sensitive keys for storage.

### Aes Ranking
| Mode        | Safety (40%)  | Complex (30%) | Widely (30%)  | Score (1~10)  | Reason
|-------------|---------------|---------------|---------------|---------------|-------------------------------------------------
| **`GCM`**   | 10            | 8             | 10            | *`9.4`*       | Efficient, secure, and widely used in modern encrypted transmission protocols (such as TLS, IPSec).
| **`CTR`**   | 8             | 9             | 9             | *`8.5`*       | Efficient and easy to implement, suitable for stream data encryption, but lacks integrity protection.
| **`OCB`**   | 10            | 7             | 6             | *`8.0`*       | It has extremely high security and excellent performance, but its application scope is limited due to patent restrictions.
| **`CCM`**   | 9             | 7             | 7             | *`7.9`*       | Provides integrity protection and is suitable for embedded and low-power devices, but is slightly less efficient than GCM.
| **`WRAP`**  | 9             | 6             | 7             | *`7.7`*       | A mode dedicated to key protection, with high security but narrow application scope.
| **`XTS`**   | 8             | 6             | 8             | *`7.6`*       | The best choice for storage encryption, designed to solve the problem of disk and sector duplication, and widely used in disk encryption systems.
| **`CBC`**   | 7             | 7             | 8             | *`7.5`*       | Traditional mode, suitable for old systems, but vulnerable to padding attacks.
| **`CFB`**   | 6             | 8             | 6             | *`6.9`*       | Suitable for streaming data encryption, but gradually replaced by more efficient modes.
| **`OFB`**   | 6             | 8             | 5             | *`6.5`*       | Similar to CTR, but lacks built-in integrity protection and has limited applications.
| **`ECB`**   | 3             | 10            | 2             | *`5.2`*       | Simple and efficient, but extremely unsafe, not recommended.

### *Aes Scoring formula*
 - Total score = (Security × 40%) + (Complexity × 30%) + (Broadness × 30%)
 - Security : Evaluated based on resistance to attacks, integrity protection and uniqueness requirements.
 - Complexity : Consider the difficulty, efficiency, and user-friendliness of implementation.
 - Extensiveness : Based on current technical standards and actual application frequency.

### *Aes Instruction Usage*

#### *Aes example shell*
```sh
#!/bin/bash
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
| Mode       | Introduction  | Demand Introduction           | Use
|------------|---------------|-------------------------------|-------------------------------------------------------------------------
| **`CBC`**  | `-cbc`        | `-key` `-iv` `-pad`           | Commonly used for file encryption or block data encryption in legacy systems.
| **`CFB`**  | `-cfb`        | `-key` `-iv` `-seg`           | Suitable for streaming data encryption, such as real-time communication systems.
| **`OFB`**  | `-ofb`        | `-key` `-iv`                  | Often used in telecommunication or hardware encryption where stream mode is needed.
| **`ECB`**  | `-ecb`        | `-key` `-pad`                 | Limited to single block encryption, not recommended for general use due to low security.
| **`WRAP`** | `-wrap`       | `-key` `-kek` `-wrapkey`      | Used for key wrapping and management, ensuring secure storage or transfer of keys.

### Ranking
| Mode        | Safety (40%)  | Complex (30%) | Widely (30%)  | Score (1~10)  | Reason
|-------------|---------------|---------------|---------------|---------------|----------------------------------------------------------------
| **`WRAP`**  | 6             | 6             | 5             | *`5.7`*       | Dedicated to key management, it has high security, but its application scope is narrow and its 3DES encryption performance is low.
| **`CBC`**   | 5             | 6             | 6             | *`5.6`*       | A common pattern in legacy systems, suitable for block encryption, but security is limited by IV management and the risk of padding attacks.
| **`CFB`**   | 4             | 6             | 4             | *`4.6`*       | Stream encryption mode is suitable for old instant messaging. It has insufficient security and relatively poor performance, and its application is gradually decreasing.
| **`OFB`**   | 4             | 6             | 3             | *`4.3`*       | Similar to CFB, but with a simpler mode, narrower application, and no integrity protection.
| **`ECB`**   | 2             | 8             | 2             | *`3.4`*       | Simple and efficient, but extremely insecure, it is only suitable for special scenarios without sensitive data (such as data alignment testing).

### *Des Scoring formula*
 - Total score = (Security × 40%) + (Complexity × 30%) + (Broadness × 30%)
 - Security : Evaluated based on resistance to attacks, integrity protection and uniqueness requirements.
 - Complexity : Consider the difficulty, efficiency, and user-friendliness of implementation.
 - Extensiveness : Based on current technical standards and actual application frequency.

### *Des Instruction Usage*

#### *Des example shell*
```sh
#!/bin/bash
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

### Salt Addition Method
- `-salt`: Add salt content in hash calculation.
- `-fir`: Add salt at the beginning (front) of the input data.
- `-mid`: Add salt at the middle (center) of the input data.
- `-las`: Add salt at the end (tail) of the input data.

### Sha3-KE
SHA3-KE (SHA3 with Keyed-Hash): This variant supports arbitrary-length hash outputs. You can specify the length of the hash output with the `-len` flag. The supported lengths are typically 128-bit and 256-bit, but they can be configured to any length required for specific cryptographic tasks.

### Hash Calculation Introduction
| Hash Type          | Introduction      | Variable Introduction                 | Use
|--------------------|-------------------|---------------------------------------|------------------------------------------------------------
| **`MD5`**          | `-md5`            | `-salt` `-fir` `-mid` `-las`          | Used for non-secure checksum calculations or quick data integrity checks.
| **`MD5-SHA1`**     | `-md5-sha1`       | `-salt` `-fir` `-mid` `-las`          | Combines MD5 and SHA1 for legacy TLS 1.2 applications, but not recommended anymore.
| **`SHA1`**         | `-sha1`           | `-salt` `-fir` `-mid` `-las`          | Deprecated but still used for legacy systems or low-security requirements.
| **`SHA2-224`**     | `-sha2-224`       | `-salt` `-fir` `-mid` `-las`          | Suitable for lightweight applications in embedded systems or IoT devices.
| **`SHA2-256`**     | `-sha2-256`       | `-salt` `-fir` `-mid` `-las`          | Industry-standard hash for digital signatures, certificates, and general security.
| **`SHA2-384`**     | `-sha2-384`       | `-salt` `-fir` `-mid` `-las`          | Provides additional security for sensitive applications like blockchain or finance.
| **`SHA2-512`**     | `-sha2-512`       | `-salt` `-fir` `-mid` `-las`          | Suitable for high-security requirements, but slower than SHA2-256.
| **`SHA2-512-224`** | `-sha2-512-224`   | `-salt` `-fir` `-mid` `-las`          | Truncated version of SHA2-512, ideal for resource-constrained environments.
| **`SHA2-512-256`** | `-sha2-512-256`   | `-salt` `-fir` `-mid` `-las`          | Truncated SHA2-512 variant, balancing security and performance.
| **`SHA3-224`**     | `-sha3-224`       | `-salt` `-fir` `-mid` `-las`          | Lightweight and secure, suitable for IoT or compact applications.
| **`SHA3-256`**     | `-sha3-256`       | `-salt` `-fir` `-mid` `-las`          | High-security applications like cryptographic signatures and secure protocols.
| **`SHA3-384`**     | `-sha3-384`       | `-salt` `-fir` `-mid` `-las`          | Used in scenarios requiring stronger security than SHA3-256, but with larger output.
| **`SHA3-512`**     | `-sha3-512`       | `-salt` `-fir` `-mid` `-las`          | Maximum security applications, often used in cryptography or digital certificates.
| **`SHA3-KE-128`**  | `-sha3-ke-128`    | `-salt` `-fir` `-mid` `-las` `-len`   | Variable-length output for specific cryptographic tasks requiring 128-bit security.
| **`SHA3-KE-256`**  | `-sha3-ke-256`    | `-salt` `-fir` `-mid` `-las` `-len`   | Variable-length output for flexible cryptographic needs with higher security.
| **`BLAKE2S-256`**  | `-blake2s-256`    | `-salt` `-fir` `-mid` `-las`          | Efficient for constrained environments like IoT or small devices.
| **`BLAKE2B-512`**  | `-blake2b-512`    | `-salt` `-fir` `-mid` `-las`          | High-efficiency hashing for large-scale applications or high-security needs.
| **`SM3`**          | `-sm3`            | `-salt` `-fir` `-mid` `-las`          | Cryptographic hash standard in China, suitable for regulatory compliance.
| **`RIPEMD160`**    | `-sm3`            | `-salt` `-fir` `-mid` `-las`          | Used in specific scenarios like Bitcoin addresses, limited in modern applications.

### Ranking
| Hash Type          | Safety (40%)  | Complex (30%) | Widely (30%)  | Score (1~10)  | Reason
|--------------------|---------------|---------------|---------------|---------------|-------------------------------------------------------------------------
| **`SHA3-256`**     | 10            | 8             | 9             | *`9.1`*       | It has high security, strong anti-collision ability, and gradually increases in popularity, making it suitable for cryptographic applications and scenarios with high security requirements.
| **`SHA2-256`**     | 9             | 8             | 10            | *`9.0`*       | Industry standard, widely used, strong anti-attack capability, suitable for most application scenarios.
| **`BLAKE2B-512`**  | 9             | 9             | 8             | *`8.9`*       | Efficient and safe, supports configurable length output, suitable for performance-sensitive applications, and second only to the SHA series in popularity.
| **`SHA3-512`**     | 10            | 7             | 7             | *`8.7`*       | Provides the highest security, but is not as widely used as SHA2.
| **`SHA2-512`**     | 9             | 8             | 8             | *`8.7`*       | It is suitable for scenarios with high security requirements, such as digital signatures and blockchain, but its computational efficiency is slightly lower.
| **`SHA3-384`**     | 10            | 7             | 6             | *`8.5`*       | High security, suitable for scenarios that require higher security, but its application popularity is limited.
| **`SHA2-384`**     | 9             | 7             | 7             | *`8.2`*       | Suitable for applications with medium to high security requirements. It has a higher computational cost and is less popular than SHA2-256.
| **`SHA3-224`**     | 9             | 8             | 6             | *`8.0`*       | It is suitable for scenarios that require lightweight and high security, and has great potential for future applications.
| **`SHA2-224`**     | 8             | 8             | 7             | *`7.9`*       | The choice for lightweight security requirements, suitable for embedded applications.
| **`BLAKE2S-256`**  | 8             | 9             | 6             | *`7.9`*       | It is efficient and lightweight, suitable for scenarios with limited resources, such as IoT devices, but its application popularity is slightly lower.
| **`SM3`**          | 8             | 7             | 7             | *`7.8`*       | It is suitable for Chinese cryptographic standard scenarios. Its collision resistance and security are not as good as SHA3, but it has advantages in specific applications.
| **`RIPEMD160`**    | 7             | 8             | 7             | *`7.5`*       | Used in specific scenarios such as Bitcoin address generation, with limited security and popularity and moderate performance.
| **`SHA3-KE-256`**  | 9             | 8             | 5             | *`7.5`*       | Variable output length, suitable for flexible scenarios, high security, but relatively low popularity.
| **`SHA3-KE-128`**  | 8             | 8             | 5             | *`7.3`*       | Variable output length, suitable for flexible scenarios, but less secure and popular than SHA3-KE-256.
| **`SHA2-512-256`** | 9             | 7             | 6             | *`7.3`*       | A truncated version of SHA-512, suitable for scenarios that require a fixed output length and medium to high security.
| **`SHA2-512-224`** | 8             | 7             | 6             | *`7.1`*       | A truncated version of SHA-512 that has similar applications to SHA2-224, but is less commonly used in real-world applications.
| **`SHA1`**         | 5             | 8             | 6             | *`6.2`*       | It is considered unsafe but still has legacy applications in old systems suitable for low security requirements.
| **`MD5-SHA1`**     | 5             | 9             | 5             | *`6.0`*       | Related to legacy applications in TLS 1.2, but not as secure.
| **`MD5`**          | 3             | 9             | 6             | *`5.4`*       | Fast but completely insecure, only suitable for non-security verification scenarios.

### *Scoring formula*
 - Total score = (Security × 40%) + (Complexity × 30%) + (Broadness × 30%)
 - Security : Evaluated based on resistance to attacks, integrity protection and uniqueness requirements.
 - Complexity : Consider the difficulty, efficiency, and user-friendliness of implementation.
 - Extensiveness : Based on current technical standards and actual application frequency.

### *Hash Instruction Usage*

#### *Hash example shell*
```sh
#!/bin/bash
# Example Hash Instructions
# Hash Settings...
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

## **RSA Cryptography**
RSA (Rivest–Shamir–Adleman) is a widely used public-key cryptography algorithm for secure data transmission and digital signatures.
It enables secure communication by using a pair of keys: a public key for encryption and a private key for decryption.

### Rsa Support Features
1. Key Generation
2. Parameter Generation
3. Key Export Parameter
4. Parameter Export Key
5. Check if the Key is Valid
6. Encryption
7. Decryption
8. Digital Signatures
9. Signature Verification

### Rsa Key Specifications
Key Size: 1024-bit, 2048-bit, 3072-bit, 4096-bit, 6144-bit, 8192-bit, 12288-bit, 16384-bit etc, You can also use unconventional lengths, which you can define yourself.
Format: PEM (Privacy-Enhanced Mail) or DER (Distinguished Encoding Rules).
Public Key: Used to encrypt data or verify digital signatures.
Private Key: Used to decrypt data or create digital signatures.

### Rsa Cryptography Introduction
| Feature                  | Mode      | Required Arguments                                                             | Description                                                                          |
|--------------------------|-----------|--------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| **`Generate Paramter`**  | `-gen`    | `-param <size>`                                                                | Create a key of your specified size, and export it to Base Encoding or File formats. |
| **`Generate Key`**       | `-gen`    | `-key <size>` `-pass <password>`                                               | Creates a key of a specified size and exports it to PEM, DER or other file formats.  |
| **`Export to Paramter`** | `-exp`    | `-param` `-pub [--keys-way]` `-priv [--keys-way]` or `[--paramters-list]`      | Export the Rsa key to Rsa Parameters.                                                |
| **`Export to Key`**      | `-exp`    | `-key` `-param [--way]`                                                        | Export the Rsa Parameters to Rsa key.                                                |
| **`Check Public Key`**   | `-chk`    | `-pub [--keys-way]`                                                            | Check if the Rsa Public Key is Valid.                                                |
| **`Check Private Key`**  | `-chk`    | `-priv [--keys-way]` `-pass <password>`                                        | Check if the Rsa Private Key is Valid.                                               |
| **`Encryption`**         | `-en`     | `-pub [--keys-way]` `-pt [--way] <plain-text>`                                 | Encrypts plaintext using a public key.                                               |
| **`Decryption`**         | `-de`     | `-priv [--keys-way]` `-pass <password>` `-ct [--way] <cipher-text>`            | Decrypts ciphertext using a private key.                                             |
| **`Signed`**             | `-sign`   | `-priv [--keys-way]` `-pass <password>` `-data [--way]` `-hash [--hash-type]`  | Generates a digital signature for the given plaintext using a private key.           |
| **`Verify`**             | `-ver`    | `-pub [--keys-way]` `-data [--way]` `-sg [--way]` `-hash [--hash-type]`        | Verifies a digital signature using the corresponding public key.                     |

   - The `<size>` when creating a key can be adjusted according to your needs.
   - `<password>` is only used when you need to operate the PEM private key. You can also leave it blank, which means that the key is not encrypted with the PEM password.
   - `<plain-text>` is your plain text, it can be any data.
   - `<cipher-text>` is your cipher text, which is your encrypted data.
   - Read the [*`[--keys-way]`*](#explanation-of---keys-way)
   - Read the [*`[--way]`*](#explanation-of---way)
   - Read the [*`[--paramters-list]`*](#explanation-of---paramters-list)
   - Read the [*`[--hash-type]`*](#explanation-of---hash-type)

### *Rsa Instruction Usage*

#### *Rsa example shell*
```sh
#!/bin/bash
# Example Rsa Instructions
# Rsa Settings...
BASE="-base16"
PEM_ROOT_FILE="pem-pkey"
DER_ROOT_FILE="der-pkey"
PARAM_FILE="paramters.bin"
RESULT_FILE="encryption.bin"
SIGNATURE_FILE="signature.bin"
RSA_PEM_PUB=$(cat <<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp6dycJXIORK+KCoiJkTb
ByrhMq6RdtDzU3zAkScCZbNclNe6pIAmVbgnNWyih6sL6nwzYbe5O631bUPUPfaa
3bDhDJwxSvqna8FRa81tLMYSHjX9qfu1WFnwcrGaiBDtdJT5DdbxKIJNth+KVFTx
64RrEDkN5FJQhVAKuA6YXhwI2MS9pQD9t1P4JQq7qZ1hli/hnFfKFNva6AyBiQwO
JhqbnYTiwgwfd5iWZCCKUnOkjdhGPKPuf1zOHz2GwYxc84nLgypx8FAR3brVV5mY
eT2pXPvCzmDaVHEDe/ZbmyJv26A8gJV9hLszbC8aEc3MrJaLrED6FaIysLWVmg3E
lQIDAQAB
-----END PUBLIC KEY-----
EOF
)
RSA_PEM_PRIV=$(cat <<EOF
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCnp3Jwlcg5Er4o
KiImRNsHKuEyrpF20PNTfMCRJwJls1yU17qkgCZVuCc1bKKHqwvqfDNht7k7rfVt
Q9Q99prdsOEMnDFK+qdrwVFrzW0sxhIeNf2p+7VYWfBysZqIEO10lPkN1vEogk22
H4pUVPHrhGsQOQ3kUlCFUAq4DpheHAjYxL2lAP23U/glCrupnWGWL+GcV8oU29ro
DIGJDA4mGpudhOLCDB93mJZkIIpSc6SN2EY8o+5/XM4fPYbBjFzzicuDKnHwUBHd
utVXmZh5Palc+8LOYNpUcQN79lubIm/boDyAlX2EuzNsLxoRzcyslousQPoVojKw
tZWaDcSVAgMBAAECggEAP9C120FhEa27Xqrj4wKLePYSUHE+tIl/Mbn1Wby4ZcTg
BuRPmL/ZZePrs2o0rFL9bwr0EiGHYGjzV9zPCXGb8v99VPofHoefpGR/mYkmWqu0
5HWoprXv+83Of6Dh+Hcjsq5XOwnOwbkQhiXtD7rT6SdFYJIeKVi5+D1/ZTqaxMVJ
LX6/9w3eWJNletLfbpqWo6jU2WdEBWB/I4UsaIM566hb61FlbM0AjFQfQIKYS8rR
vKsSI0BY439Nb/7Dqhv+rkH0wLd16thbAEXHJdvsYsd2gGYKtGMSb+5o669HCqum
8IF8DnaXBnYFor4IqxdtMw3o/Xt30On59LfkFOWBpwKBgQDGYmTQT9NFPlWn+9DY
6re16dr7PRgGqBRZGfAz7P/IfXl9poc4D11lrlEOwaEQLmQ3JWI75eXnFTgjx1nC
iMlKf1fEey8ctdEzUbcKcneQNWXTDX6fen8rmXDtHdap59iC6NIOxYYASnGMd+d+
Llb++kkEk29pAhUZ2ISem8j3tQKBgQDYWEzaBpZeGT/K6CMREgFZAmA3D4avoM0n
IKzZ6VoAzIvy/7iIWEIuzH9GLrPWmY5lAw6gmHMx9OoTBDT4MvbCJeK1RUQKS3+c
sE/59GPQvllBk93KUUuljzS9bxkLKHqaMlFMEi9cIHdbY4fR+sdpZI+AjuJ2BWly
N5H8xeflYQKBgEvnS7FUSX592iIavA6yx7WHk2x7NJ0fZCGvRfNoI3mfYION2sC9
SDvmVUczGJ/rUBa1a/+E99DRkphF5vcChRnG3Vrk0uLGQhPDmSgbIdoARERbLm5w
XQXegJGI0CBT/8gesnhKZPnpgcZ//geOTWTjeFqS2pav4EjySdOxwVPdAoGBAKSS
1zNrm2tNjceOu047AidxtTttZimoCyfepV7HMp40+6kIepnNedsb2R3MXSW8fiO9
JZ1pGwg/pOh+ZMUCD9A0/bajUFT8hcDuJoigLmYWxtMp5qgHG6J/w8DvCIACdPFj
oZBarQhJ8kHk/ubu/E7iHn/PMdpR15r5Ruagrf1BAoGAU5q/bP7zT8HNSBdrZ5zW
lgYIuRd7qcMlb7LoOVt9lsV8Ee1riIm7JkxFq4esGIXK7AZODT983TAmGlIt/B9u
iLN4+WuEPzwTq5YENM4k/slrA49VYBUaYR3zBwUZFA5Qjt85hhWjX7jrdx07qt+g
02ImPBDZB3KsD6Q8TWLzdtk=
-----END PRIVATE KEY-----
EOF
)
RSA_DER_PUB="30820122300D06092A864886F70D01010105000382010F003082010A0282010100A7A7727095C83912BE282A222644DB072AE132AE9176D0F3537CC091270265B35C94D7BAA4802655B827356CA287AB0BEA7C3361B7B93BADF56D43D43DF69ADDB0E10C9C314AFAA76BC1516BCD6D2CC6121E35FDA9FBB55859F072B19A8810ED7494F90DD6F128824DB61F8A5454F1EB846B10390DE4525085500AB80E985E1C08D8C4BDA500FDB753F8250ABBA99D61962FE19C57CA14DBDAE80C81890C0E261A9B9D84E2C20C1F77989664208A5273A48DD8463CA3EE7F5CCE1F3D86C18C5CF389CB832A71F05011DDBAD5579998793DA95CFBC2CE60DA5471037BF65B9B226FDBA03C80957D84BB336C2F1A11CDCCAC968BAC40FA15A232B0B5959A0DC4950203010001"
RSA_DER_PRIV="308204A30201000282010100A7A7727095C83912BE282A222644DB072AE132AE9176D0F3537CC091270265B35C94D7BAA4802655B827356CA287AB0BEA7C3361B7B93BADF56D43D43DF69ADDB0E10C9C314AFAA76BC1516BCD6D2CC6121E35FDA9FBB55859F072B19A8810ED7494F90DD6F128824DB61F8A5454F1EB846B10390DE4525085500AB80E985E1C08D8C4BDA500FDB753F8250ABBA99D61962FE19C57CA14DBDAE80C81890C0E261A9B9D84E2C20C1F77989664208A5273A48DD8463CA3EE7F5CCE1F3D86C18C5CF389CB832A71F05011DDBAD5579998793DA95CFBC2CE60DA5471037BF65B9B226FDBA03C80957D84BB336C2F1A11CDCCAC968BAC40FA15A232B0B5959A0DC4950203010001028201003FD0B5DB416111ADBB5EAAE3E3028B78F61250713EB4897F31B9F559BCB865C4E006E44F98BFD965E3EBB36A34AC52FD6F0AF41221876068F357DCCF09719BF2FF7D54FA1F1E879FA4647F9989265AABB4E475A8A6B5EFFBCDCE7FA0E1F87723B2AE573B09CEC1B9108625ED0FBAD3E9274560921E2958B9F83D7F653A9AC4C5492D7EBFF70DDE5893657AD2DF6E9A96A3A8D4D9674405607F23852C688339EBA85BEB51656CCD008C541F4082984BCAD1BCAB12234058E37F4D6FFEC3AA1BFEAE41F4C0B775EAD85B0045C725DBEC62C77680660AB463126FEE68EBAF470AABA6F0817C0E7697067605A2BE08AB176D330DE8FD7B77D0E9F9F4B7E414E581A702818100C66264D04FD3453E55A7FBD0D8EAB7B5E9DAFB3D1806A8145919F033ECFFC87D797DA687380F5D65AE510EC1A1102E643725623BE5E5E7153823C759C288C94A7F57C47B2F1CB5D13351B70A7277903565D30D7E9F7A7F2B9970ED1DD6A9E7D882E8D20EC586004A718C77E77E2E56FEFA4904936F69021519D8849E9BC8F7B502818100D8584CDA06965E193FCAE823111201590260370F86AFA0CD2720ACD9E95A00CC8BF2FFB88858422ECC7F462EB3D6998E65030EA0987331F4EA130434F832F6C225E2B545440A4B7F9CB04FF9F463D0BE594193DDCA514BA58F34BD6F190B287A9A32514C122F5C20775B6387D1FAC769648F808EE2760569723791FCC5E7E5610281804BE74BB154497E7DDA221ABC0EB2C7B587936C7B349D1F6421AF45F36823799F60838DDAC0BD483BE6554733189FEB5016B56BFF84F7D0D1929845E6F7028519C6DD5AE4D2E2C64213C399281B21DA0044445B2E6E705D05DE809188D02053FFC81EB2784A64F9E981C67FFE078E4D64E3785A92DA96AFE048F249D3B1C153DD02818100A492D7336B9B6B4D8DC78EBB4E3B022771B53B6D6629A80B27DEA55EC7329E34FBA9087A99CD79DB1BD91DCC5D25BC7E23BD259D691B083FA4E87E64C5020FD034FDB6A35054FC85C0EE2688A02E6616C6D329E6A8071BA27FC3C0EF08800274F163A1905AAD0849F241E4FEE6EEFC4EE21E7FCF31DA51D79AF946E6A0ADFD41028180539ABF6CFEF34FC1CD48176B679CD6960608B9177BA9C3256FB2E8395B7D96C57C11ED6B8889BB264C45AB87AC1885CAEC064E0D3F7CDD30261A522DFC1F6E88B378F96B843F3C13AB960434CE24FEC96B038F5560151A611DF3070519140E508EDF398615A35FB8EB771D3BAADFA0D362263C10D90772AC0FA43C4D62F376D9"
N="A7A7727095C83912BE282A222644DB072AE132AE9176D0F3537CC091270265B35C94D7BAA4802655B827356CA287AB0BEA7C3361B7B93BADF56D43D43DF69ADDB0E10C9C314AFAA76BC1516BCD6D2CC6121E35FDA9FBB55859F072B19A8810ED7494F90DD6F128824DB61F8A5454F1EB846B10390DE4525085500AB80E985E1C08D8C4BDA500FDB753F8250ABBA99D61962FE19C57CA14DBDAE80C81890C0E261A9B9D84E2C20C1F77989664208A5273A48DD8463CA3EE7F5CCE1F3D86C18C5CF389CB832A71F05011DDBAD5579998793DA95CFBC2CE60DA5471037BF65B9B226FDBA03C80957D84BB336C2F1A11CDCCAC968BAC40FA15A232B0B5959A0DC495"
E="010001"
D="3FD0B5DB416111ADBB5EAAE3E3028B78F61250713EB4897F31B9F559BCB865C4E006E44F98BFD965E3EBB36A34AC52FD6F0AF41221876068F357DCCF09719BF2FF7D54FA1F1E879FA4647F9989265AABB4E475A8A6B5EFFBCDCE7FA0E1F87723B2AE573B09CEC1B9108625ED0FBAD3E9274560921E2958B9F83D7F653A9AC4C5492D7EBFF70DDE5893657AD2DF6E9A96A3A8D4D9674405607F23852C688339EBA85BEB51656CCD008C541F4082984BCAD1BCAB12234058E37F4D6FFEC3AA1BFEAE41F4C0B775EAD85B0045C725DBEC62C77680660AB463126FEE68EBAF470AABA6F0817C0E7697067605A2BE08AB176D330DE8FD7B77D0E9F9F4B7E414E581A7"
P="C66264D04FD3453E55A7FBD0D8EAB7B5E9DAFB3D1806A8145919F033ECFFC87D797DA687380F5D65AE510EC1A1102E643725623BE5E5E7153823C759C288C94A7F57C47B2F1CB5D13351B70A7277903565D30D7E9F7A7F2B9970ED1DD6A9E7D882E8D20EC586004A718C77E77E2E56FEFA4904936F69021519D8849E9BC8F7B5"
Q="D8584CDA06965E193FCAE823111201590260370F86AFA0CD2720ACD9E95A00CC8BF2FFB88858422ECC7F462EB3D6998E65030EA0987331F4EA130434F832F6C225E2B545440A4B7F9CB04FF9F463D0BE594193DDCA514BA58F34BD6F190B287A9A32514C122F5C20775B6387D1FAC769648F808EE2760569723791FCC5E7E561"
DP="4BE74BB154497E7DDA221ABC0EB2C7B587936C7B349D1F6421AF45F36823799F60838DDAC0BD483BE6554733189FEB5016B56BFF84F7D0D1929845E6F7028519C6DD5AE4D2E2C64213C399281B21DA0044445B2E6E705D05DE809188D02053FFC81EB2784A64F9E981C67FFE078E4D64E3785A92DA96AFE048F249D3B1C153DD"
DQ="A492D7336B9B6B4D8DC78EBB4E3B022771B53B6D6629A80B27DEA55EC7329E34FBA9087A99CD79DB1BD91DCC5D25BC7E23BD259D691B083FA4E87E64C5020FD034FDB6A35054FC85C0EE2688A02E6616C6D329E6A8071BA27FC3C0EF08800274F163A1905AAD0849F241E4FEE6EEFC4EE21E7FCF31DA51D79AF946E6A0ADFD41"
QI="539ABF6CFEF34FC1CD48176B679CD6960608B9177BA9C3256FB2E8395B7D96C57C11ED6B8889BB264C45AB87AC1885CAEC064E0D3F7CDD30261A522DFC1F6E88B378F96B843F3C13AB960434CE24FEC96B038F5560151A611DF3070519140E508EDF398615A35FB8EB771D3BAADFA0D362263C10D90772AC0FA43C4D62F376D9"

# RSA Generate Key (PEM)
./aisio -rsa -generate -keys 2048 -out -pem

# RSA Generate Key (PEM File)
./aisio -rsa -generate -keys 2048 -out -pem -file "$PEM_ROOT_FILE"

# RSA Generate Key (DER)
./aisio -rsa -generate -keys 2048 -out -der "$BASE"

# RSA Generate Key (DER File)
./aisio -rsa -generate -keys 2048 -out -der -file "$DER_ROOT_FILE"

# RSA Generate Paramters (Base Encoding)
./aisio -rsa -generate -params 2048 -out "$BASE"

# RSA Generate Paramters (Paramters File)
./aisio -rsa -generate -params 2048 -out -file "$PARAM_FILE"

# RSA Export To Paramters (PEM)
./aisio -rsa -export -params -pub -pem "$RSA_PEM_PUB" -priv -pem "$RSA_PEM_PRIV" -out "$BASE"

# RSA Export To Paramters (PEM File + Paramters File)
./aisio -rsa -export -params -pub -pem -file "$PEM_ROOT_FILE"-pub.pem -priv -pem -file "$PEM_ROOT_FILE"-priv.pem -out -file "$PARAM_FILE"

# RSA Export To Paramters (DER)
./aisio -rsa -export -params -pub -der "$BASE" "$RSA_DER_PUB" -priv -der "$BASE" "$RSA_DER_PRIV" -out "$BASE"

# RSA Export To Paramters (DER File + Paramters File)
./aisio -rsa -export -params -pub -der -file "$DER_ROOT_FILE"-pub.der -priv -der -file "$DER_ROOT_FILE"-priv.der -out -file "$PARAM_FILE"

# RSA Export To Public Key and Private Key (PEM)
./aisio -rsa -export -keys -params "$BASE" -n "$N" -e "$E" -d "$D" -p "$P" -q "$Q" -dp "$DP" -dq "$DQ" -qi "$QI" -out -pem

# RSA Export To Public Key and Private Key (Paramters File + PEM File)
./aisio -rsa -export -keys -params -file "$PARAM_FILE" -out -pem -file "$PEM_ROOT_FILE"

# RSA Export To Public Key and Private Key (DER)
./aisio -rsa -export -keys -params "$BASE" -n "$N" -e "$E" -d "$D" -p "$P" -q "$Q" -dp "$DP" -dq "$DQ" -qi "$QI" -out -der "$BASE"

# RSA Export To Public Key and Private Key (Paramters File + DER File)
./aisio -rsa -export -keys -params -file "$PARAM_FILE" -out -der -file "$DER_ROOT_FILE"

# RSA Check Public Key (PEM)
./aisio -rsa -check -pub -pem "$RSA_PEM_PUB"

# RSA Check Private Key (PEM)
./aisio -rsa -check -priv -pem "$RSA_PEM_PRIV"

# RSA Check Public Key (PEM File)
./aisio -rsa -check -pub -pem -file "$PEM_ROOT_FILE"-pub.pem

# RSA Check Private Key (PEM File)
./aisio -rsa -check -priv -pem -file "$PEM_ROOT_FILE"-priv.pem

# RSA Check Public Key (DER)
./aisio -rsa -check -pub -der "$BASE" "$RSA_DER_PUB"

# RSA Check Private Key (DER)
./aisio -rsa -check -priv -der "$BASE" "$RSA_DER_PRIV"

# RSA Check Public Key (DER File)
./aisio -rsa -check -pub -der -file "$DER_ROOT_FILE"-pub.der

# RSA Check Private Key (DER File)
./aisio -rsa -check -priv -der -file "$DER_ROOT_FILE"-priv.der

# RSA Encryption (PEM)
RESULT=$(./aisio -rsa -encrypt -pub -pem "$RSA_PEM_PUB" -plain-text "This is Encryption/Decryption by RSA PEM 2048 Key." -out "$BASE" | grep -Pzo '(?<=<RSA Encrypt>\n)(.*?)(?=\nElapsed time:)\n' | tr -d '\0')
echo "$RESULT"

# RSA Decryption (PEM)
./aisio -rsa -decrypt -priv -pem "$RSA_PEM_PRIV" -cipher-text "$BASE" "$RESULT"

# RSA Encryption (PEM File)
./aisio -rsa -encrypt -pub -pem -file "$PEM_ROOT_FILE"-pub.pem -plain-text "This is Encryption/Decryption by RSA PEM 2048 Key." -out -file "$RESULT_FILE"

# RSA Decryption (PEM File)
./aisio -rsa -decrypt -priv -pem -file "$PEM_ROOT_FILE"-priv.pem -cipher-text -file "$RESULT_FILE"

# RSA Encryption (DER)
RESULT=$(./aisio -rsa -encrypt -pub -der "$BASE" "$RSA_DER_PUB" -plain-text "This is Encryption/Decryption by RSA DER 2048 Key." -out "$BASE" | grep -Pzo '(?<=<RSA Encrypt>\n)(.*?)(?=\nElapsed time:)\n' | tr -d '\0')
echo "$RESULT"

# RSA Decryption (DER)
./aisio -rsa -decrypt -priv -der "$BASE" "$RSA_DER_PRIV" -cipher-text "$BASE" "$RESULT"

# RSA Encryption (DER File)
./aisio -rsa -encrypt -pub -der -file "$DER_ROOT_FILE"-pub.der -plain-text "This is Encryption/Decryption by RSA DER 2048 Key." -out -file "$RESULT_FILE"

# RSA Decryption (DER File)
./aisio -rsa -decrypt -priv -der -file "$DER_ROOT_FILE"-priv.der -cipher-text -file "$RESULT_FILE"

# RSA Signed (PEM)
RESULT=$(./aisio -rsa -signed -priv -pem "$RSA_PEM_PRIV" -hash -sha3-512 -data "This is Signed/Verify Data by RSA PEM 2048 Key." -out "$BASE" | grep -Pzo '(?<=<RSA Signed>\n)(.*?)(?=\nElapsed time:)\n' | tr -d '\0')
echo "$RESULT"

# RSA Verify (PEM)
./aisio -rsa -verify -pub -pem "$RSA_PEM_PUB" -hash -sha3-512 -data "This is Signed/Verify Data by RSA PEM 2048 Key." -signature "$BASE" "$RESULT"

# RSA Signed (PEM File)
./aisio -rsa -signed -priv -pem -file "$PEM_ROOT_FILE"-priv.pem -hash -sha3-512 -data "This is Signed/Verify Data by RSA PEM 2048 Key." -out -file "$SIGNATURE_FILE"

# RSA Verify (PEM File)
./aisio -rsa -verify -pub -pem -file "$PEM_ROOT_FILE"-pub.pem -hash -sha3-512 -data "This is Signed/Verify Data by RSA PEM 2048 Key." -signature -file "$SIGNATURE_FILE"

# RSA Signed (DER)
RESULT=$(./aisio -rsa -signed -priv -der "$BASE" "$RSA_DER_PRIV" -hash -sha3-512 -data "This is Signed/Verify Data by RSA DER 2048 Key." -out "$BASE" | grep -Pzo '(?<=<RSA Signed>\n)(.*?)(?=\nElapsed time:)\n' | tr -d '\0')
echo "$RESULT"

# RSA Verify (DER)
./aisio -rsa -verify -pub -der "$BASE" "$RSA_DER_PUB" -hash -sha3-512 -data "This is Signed/Verify Data by RSA DER 2048 Key." -signature "$BASE" "$RESULT"

# RSA Signed (DER File)
./aisio -rsa -signed -priv -der -file "$DER_ROOT_FILE"-priv.der -hash -sha3-512 -data "This is Signed/Verify Data by RSA DER 2048 Key." -out -file "$SIGNATURE_FILE"

# RSA Verify (DER File)
./aisio -rsa -verify -pub -der -file "$DER_ROOT_FILE"-pub.der -hash -sha3-512 -data "This is Signed/Verify Data by RSA DER 2048 Key." -signature -file "$SIGNATURE_FILE"
```

---

### *Explanation of `[--keys-way]`*
   01. `-pem`                               -> PEM Raw data.
   02. `-pem -f <path>` `-pem -file <path>` -> PEM Archival data.
   03. `-der`                               -> DER Raw data.
   04. `-der -b10` `-der -base10`           -> DER Base10 data.
   05. `-der -b16` `-der -base16`           -> DER Base16 data.
   06. `-der -b32` `-der -base32`           -> DER Base32 data.
   07. `-der -b58` `-der -base58`           -> DER Base58 data.
   08. `-der -b62` `-der -base62`           -> DER Base62 data.
   09. `-der -b64` `-der -base64`           -> DER Base64 data.
   10. `-der -b85` `-der -base85`           -> DER Base85 data.
   11. `-der -b91` `-der -base91`           -> DER Base91 data.
   12. `-der -f <path>` `-der -file <path>` -> DER Archival data.

### *Explanation of `[--way]`*
   01. `<content>`                -> Raw data.
   02. `-b10` `-base10`           -> Base10 data.
   03. `-b16` `-base16`           -> Base16 data.
   04. `-b32` `-base32`           -> Base32 data.
   05. `-b58` `-base58`           -> Base58 data.
   06. `-b62` `-base62`           -> Base62 data.
   07. `-b64` `-base64`           -> Base64 data.
   08. `-b85` `-base85`           -> Base85 data.
   09. `-b91` `-base91`           -> Base91 data.
   10. `-f <path>` `-file <path>` -> Archival data.

### *Explanation of `[--paramters-list]`*
   1. `-n` `-modulus`                          -> Modulus data by [--way].
   2. `-e` `-public-exponent`                  -> Public Exponent data by [--way].
   3. `-d` `-private-exponent`                 -> Private Exponent data by [--way].
   4. `-p` `-prime1` `-first-prime-factor`     -> First Prime Factor data by [--way].
   5. `-q` `-prime2` `-second-prime-factor`    -> Second Prime Factor data by [--way].
   6. `-dp` `-exponent1` `-first-crt-exponent` -> First CRT Exponent data by [--way].
   7. `-dq` `-exponent2` `-second-crt-exponent`-> Second CRT Exponent data by [--way].
   8. `-qi` `-coefficient` `-crt-coefficient`  -> CRT Coefficient data by [--way].

### *Explanation of `[--hash-type]`*
   1. `-md5`                                 -> Hash MD5 Calculation.
   2. `-md5-sha1`                            -> Hash MD5-SHA1 Calculation.
   3. `-sha1`                                -> Hash SHA1 Calculation.
   4. `-sha224` `-sha2-224`                  -> Hash SHA2-224 Calculation.
   5. `-sha256` `-sha2-256`                  -> Hash SHA2-256 Calculation.
   6. `-sha384` `-sha2-384`                  -> Hash SHA2-384 Calculation.
   7. `-sha512` `-sha2-512`                  -> Hash SHA2-512 Calculation.
   8. `-sha512-224` `-sha2-512-224`          -> Hash SHA2-512-224 Calculation.
   9. `-sha512-256` `-sha2-512-256`          -> Hash SHA2-512-256 Calculation.
   10. `-sha3-224`                           -> Hash SHA3-224 Calculation.
   11. `-sha3-256`                           -> Hash SHA3-256 Calculation.
   12. `-sha3-384`                           -> Hash SHA3-384 Calculation.
   13. `-sha3-512`                           -> Hash SHA3-512 Calculation.
   14. `-shake128` `-sha3-ke-128`            -> Hash SHA3-KE-128 Calculation.
   15. `-shake256` `-sha3-ke-256`            -> Hash SHA3-KE-256 Calculation.
   16. `-blake2s` `-blake256` `-blake2s-256` -> Hash BLAKE2S-256 Calculation.
   17. `-blake2b` `-blake512` `-blake2b-512` -> Hash BLAKE2B-512 Calculation.
   18. `-sm3`                                -> Hash SM3 Calculation.
   19. `-ripemd160`                          -> Hash RIPEMD160 Calculation.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.