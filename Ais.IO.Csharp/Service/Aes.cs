using System;
using System.Collections.Generic;
using System.Linq;
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

        public byte[] ImportKey(string text)
        {
            if (!this.AcceptImportKeySize.Contains(text.Length))
                throw new FormatException("Key size must be 128, 192, 256 bits, or 16, 24, 32 bytes.");
            byte[] key = new byte[text.Length];
            byte[] keyBuffer = new byte[key.Length];
            AesIOInterop.GenerateKeyFromInput(text, keyBuffer, keyBuffer.Length);
            this.Key = keyBuffer;
            return keyBuffer;
        }

        public byte[] ImportIV(string text)
        {
            if (text.Length != 16)
                throw new FormatException("IV size must be 128 bits, or 16 bytes.");
            byte[] iv = new byte[text.Length];
            byte[] ivBuffer = new byte[iv.Length];
            AesIOInterop.GenerateIVFromInput(text, ivBuffer, ivBuffer.Length);
            this.IV = ivBuffer;
            return ivBuffer;
        }

        public byte[] CtrEncrypt(string text, byte[] key, byte[] iv)
        {
            byte[] plainText = Encoding.UTF8.GetBytes(text);
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
                COUNTER = 1,
                PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                CIPHER_TEXT = cipherTextPtr
            };

            int cipherTextLength = AesIOInterop.AesCtrEncrypt(ref encryption);
            if (cipherTextLength > 0)
                Marshal.Copy(cipherTextPtr, cipherText, 0, cipherTextLength);
            else
                cipherText = new byte[0];
            return cipherText;
        }

        public byte[] CtrDecrypt(string text, byte[] key, byte[] iv)
        {
            byte[] cipherText = Encoding.UTF8.GetBytes(text);
            byte[] plainText = new byte[cipherText.Length];

            IntPtr keyPtr = Marshal.AllocHGlobal(key.Length);
            IntPtr ivPtr = Marshal.AllocHGlobal(iv.Length);
            IntPtr cipherTextPtr = Marshal.AllocHGlobal(cipherText.Length);
            IntPtr plainTextPtr = Marshal.AllocHGlobal(plainText.Length);

            Marshal.Copy(cipherTextPtr, cipherText, 0, cipherText.Length);
            Marshal.Copy(key, 0, keyPtr, key.Length);
            Marshal.Copy(iv, 0, ivPtr, iv.Length);

            AES_CTR_DECRYPT decryption = new AES_CTR_DECRYPT
            {
                CIPHER_TEXT = cipherTextPtr,
                KEY = keyPtr,
                IV = ivPtr,
                COUNTER = 1,
                CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                PLAIN_TEXT = plainTextPtr,
            };
            int plainTextLength = AesIOInterop.AesCtrDecrypt(ref decryption);
            if (plainTextLength > 0)
                Marshal.Copy(plainTextPtr, plainText, 0, plainTextLength);
            else
                plainText = new byte[0];
            return plainText;
        }
    }
}
