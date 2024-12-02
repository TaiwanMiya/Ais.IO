using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public class Aes
    {
        private int[] AcceptGenerateKeySize = new int[]
        {
            16, 24, 32, 128, 192, 256
        };
        private int[] AcceptImportKeySize = new int[]
        {
            16, 24, 32
        };

        private byte[] Key { get; set; }
        private byte[] IV { get; set; }

        public Aes() { }

        public byte[] GenerateKey(int size)
        {
            if (!this.AcceptGenerateKeySize.Contains(size))
                throw new FormatException("Key size must be 128, 192, 256 bits, or 16, 24, 32 bytes.");
            byte[] key = size > 32
                ? new byte[size / 8]
                : new byte[size];
            AesIOInterop.GenerateKey(key, size > 32 ? size / 8 : size);
            this.Key = key;
            return key;
        }

        public byte[] GenerateIV()
        {
            byte[] iv = new byte[16];
            AesIOInterop.GenerateIV(iv, 16);
            this.IV = iv;
            return iv;
        }

        public byte[] ImportKey(string content)
        {
            if (!this.AcceptImportKeySize.Contains(content.Length))
                throw new FormatException("Key size must be 128, 192, 256 bits, or 16, 24, 32 bytes.");
            byte[] key = new byte[content.Length];
            byte[] keyBuffer = new byte[key.Length];
            AesIOInterop.GenerateKeyFromInput(content, content.Length, keyBuffer, keyBuffer.Length);
            this.Key = keyBuffer;
            return keyBuffer;
        }

        public byte[] ImportIV(string content)
        {
            if (content.Length != 16)
                throw new FormatException("IV size must be 128 bits, or 16 bytes.");
            byte[] iv = new byte[content.Length];
            byte[] ivBuffer = new byte[iv.Length];
            AesIOInterop.GenerateIVFromInput(content, content.Length, ivBuffer, ivBuffer.Length);
            this.IV = ivBuffer;
            return ivBuffer;
        }

        public byte[] CtrEncrypt(byte[] plainText, byte[] key, byte[] iv, long counter = 0)
        {
            byte[] cipherText = new byte[plainText.Length];

            IntPtr keyPtr = Marshal.AllocHGlobal(key.Length);
            IntPtr ivPtr = Marshal.AllocHGlobal(iv.Length);
            IntPtr plainTextPtr = Marshal.AllocHGlobal(plainText.Length);
            IntPtr cipherTextPtr = Marshal.AllocHGlobal(cipherText.Length);

            Marshal.Copy(plainText, 0, plainTextPtr, plainText.Length);
            Marshal.Copy(key, 0, keyPtr, key.Length);
            Marshal.Copy(iv, 0, ivPtr, iv.Length);

            AES_CTR_ENCRYPT encryption = new AES_CTR_ENCRYPT
            {
                PLAIN_TEXT = plainTextPtr,
                KEY = keyPtr,
                IV = ivPtr,
                PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                CIPHER_TEXT = cipherTextPtr,
                COUNTER = counter,
            };

            int cipherTextLength = AesIOInterop.AesCtrEncrypt(ref encryption);
            if (cipherTextLength > 0)
            {
                cipherText = new byte[cipherTextLength];
                Marshal.Copy(cipherTextPtr, cipherText, 0, cipherTextLength);
            }
            else
                cipherText = new byte[0];

            Marshal.FreeHGlobal(plainTextPtr);
            Marshal.FreeHGlobal(cipherTextPtr);
            Marshal.FreeHGlobal(keyPtr);
            Marshal.FreeHGlobal(ivPtr);
            return cipherText;
        }

        public byte[] CtrDecrypt(byte[] cipherText, byte[] key, byte[] iv, long counter = 0)
        {
            byte[] plainText = new byte[cipherText.Length];

            IntPtr keyPtr = Marshal.AllocHGlobal(key.Length);
            IntPtr ivPtr = Marshal.AllocHGlobal(iv.Length);
            IntPtr cipherTextPtr = Marshal.AllocHGlobal(cipherText.Length);
            IntPtr plainTextPtr = Marshal.AllocHGlobal(plainText.Length);

            Marshal.Copy(cipherText, 0, cipherTextPtr, cipherText.Length);
            Marshal.Copy(key, 0, keyPtr, key.Length);
            Marshal.Copy(iv, 0, ivPtr, iv.Length);

            AES_CTR_DECRYPT decryption = new AES_CTR_DECRYPT
            {
                CIPHER_TEXT = cipherTextPtr,
                KEY = keyPtr,
                IV = ivPtr,
                CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                PLAIN_TEXT = plainTextPtr,
                COUNTER = counter,
            };
            int plainTextLength = AesIOInterop.AesCtrDecrypt(ref decryption);
            if (plainTextLength > 0)
            {
                plainText = new byte[plainTextLength];
                Marshal.Copy(plainTextPtr, plainText, 0, plainTextLength);
            }
            else
                plainText = new byte[0];

            Marshal.FreeHGlobal(plainTextPtr);
            Marshal.FreeHGlobal(cipherTextPtr);
            Marshal.FreeHGlobal(keyPtr);
            Marshal.FreeHGlobal(ivPtr);
            return plainText;
        }

        public byte[] CbcEncrypt(byte[] plainText, byte[] key, byte[] iv, bool padding = true)
        {
            byte[] cipherText = new byte[plainText.Length];

            IntPtr keyPtr = Marshal.AllocHGlobal(key.Length);
            IntPtr ivPtr = Marshal.AllocHGlobal(iv.Length);
            IntPtr plainTextPtr = Marshal.AllocHGlobal(plainText.Length);
            IntPtr cipherTextPtr = Marshal.AllocHGlobal(cipherText.Length);

            Marshal.Copy(plainText, 0, plainTextPtr, plainText.Length);
            Marshal.Copy(key, 0, keyPtr, key.Length);
            Marshal.Copy(iv, 0, ivPtr, iv.Length);

            AES_CBC_ENCRYPT encryption = new AES_CBC_ENCRYPT
            {
                PLAIN_TEXT = plainTextPtr,
                KEY = keyPtr,
                IV = ivPtr,
                PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                CIPHER_TEXT = cipherTextPtr,
                PKCS7_PADDING = padding
            };

            int cipherTextLength = AesIOInterop.AesCbcEncrypt(ref encryption);
            if (cipherTextLength > 0)
            {
                cipherText = new byte[cipherTextLength];
                Marshal.Copy(cipherTextPtr, cipherText, 0, cipherTextLength);
            }
            else
                cipherText = new byte[0];

            Marshal.FreeHGlobal(plainTextPtr);
            Marshal.FreeHGlobal(cipherTextPtr);
            Marshal.FreeHGlobal(keyPtr);
            Marshal.FreeHGlobal(ivPtr);
            return cipherText;
        }

        public byte[] CbcDecrypt(byte[] cipherText, byte[] key, byte[] iv, bool padding = true)
        {
            byte[] plainText = new byte[cipherText.Length];

            IntPtr keyPtr = Marshal.AllocHGlobal(key.Length);
            IntPtr ivPtr = Marshal.AllocHGlobal(iv.Length);
            IntPtr cipherTextPtr = Marshal.AllocHGlobal(cipherText.Length);
            IntPtr plainTextPtr = Marshal.AllocHGlobal(plainText.Length);

            Marshal.Copy(cipherText, 0, cipherTextPtr, cipherText.Length);
            Marshal.Copy(key, 0, keyPtr, key.Length);
            Marshal.Copy(iv, 0, ivPtr, iv.Length);

            AES_CBC_DECRYPT decryption = new AES_CBC_DECRYPT
            {
                CIPHER_TEXT = cipherTextPtr,
                KEY = keyPtr,
                IV = ivPtr,
                CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                PLAIN_TEXT = plainTextPtr,
                PKCS7_PADDING = padding
            };
            int plainTextLength = AesIOInterop.AesCbcDecrypt(ref decryption);
            if (plainTextLength > 0)
            {
                plainText = new byte[plainTextLength];
                Marshal.Copy(plainTextPtr, plainText, 0, plainTextLength);
            }
            else
                plainText = new byte[0];

            Marshal.FreeHGlobal(plainTextPtr);
            Marshal.FreeHGlobal(cipherTextPtr);
            Marshal.FreeHGlobal(keyPtr);
            Marshal.FreeHGlobal(ivPtr);
            return plainText;
        }
    }
}
