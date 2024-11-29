using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp.Command
{
    internal class AesIO
    {
        public static void Generate()
        {
            byte[] key128 = new byte[128 / 8];
            byte[] key192 = new byte[192 / 8];
            byte[] key256 = new byte[256 / 8];
            byte[] iv = new byte[128 / 8];

            string inputKey = "Key length must be 128, 192, 256";
            byte[] inputKeyBuffer = new byte[inputKey.Length];
            string inputIV = "IvMustBe128Size.";
            byte[] inputIVBuffer = new byte[inputIV.Length];

            if (AesIOInterop.GenerateKey(key128, key128.Length) == 0)
                Console.WriteLine("Generated Key (128 bits): " + BitConverter.ToString(key128).Replace("-", ""));
            if (AesIOInterop.GenerateKey(key192, key192.Length) == 0)
                Console.WriteLine("Generated Key (192 bits): " + BitConverter.ToString(key192).Replace("-", ""));
            if (AesIOInterop.GenerateKey(key256, key256.Length) == 0)
                Console.WriteLine("Generated Key (256 bits): " + BitConverter.ToString(key256).Replace("-", ""));
            if (AesIOInterop.GenerateIV(iv, iv.Length) == 0)
                Console.WriteLine("Generated IV (128 bits): " + BitConverter.ToString(iv).Replace("-", ""));

            if (AesIOInterop.GenerateKeyFromInput(inputKey, inputKeyBuffer, inputKeyBuffer.Length) == 0)
                Console.WriteLine("Generated Key from Input (256 bits): " + BitConverter.ToString(inputKeyBuffer).Replace("-", ""));
            if (AesIOInterop.GenerateIVFromInput(inputIV, inputIVBuffer, inputIVBuffer.Length) == 0)
                Console.WriteLine("Generated Key from Input (256 bits): " + BitConverter.ToString(inputIVBuffer).Replace("-", ""));
        }

        public static void CTR(string text)
        {
            // 明文和密钥设置
            byte[] plainText = Encoding.UTF8.GetBytes(text);
            byte[] key = new byte[32];  // 假设使用 256 位的密钥
            byte[] iv = new byte[16];   // 128 位的 IV
            byte[] cipherText = new byte[plainText.Length];
            byte[] decryptedText = new byte[plainText.Length];

            // 填充随机密钥和 IV（可根据你的需求调整）
            Random rnd = new Random();
            rnd.NextBytes(key);
            rnd.NextBytes(iv);

            // 分配非托管内存
            IntPtr plainTextPtr = Marshal.AllocHGlobal(plainText.Length);
            IntPtr keyPtr = Marshal.AllocHGlobal(key.Length);
            IntPtr ivPtr = Marshal.AllocHGlobal(iv.Length);
            IntPtr cipherTextPtr = Marshal.AllocHGlobal(cipherText.Length);

            Marshal.Copy(plainText, 0, plainTextPtr, plainText.Length);
            Marshal.Copy(key, 0, keyPtr, key.Length);
            Marshal.Copy(iv, 0, ivPtr, iv.Length);

            // 设置 AES_CTR_ENCRYPT 结构体
            AES_CTR_ENCRYPT encryption = new AES_CTR_ENCRYPT
            {
                PLAIN_TEXT = plainTextPtr,
                KEY = keyPtr,
                IV = ivPtr,
                COUNTER = 0,
                PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                CIPHER_TEXT = cipherTextPtr
            };

            // 执行加密
            int cipherTextLength = AesIOInterop.AesCtrEncrypt(ref encryption);
            if (cipherTextLength > 0)
            {
                Marshal.Copy(cipherTextPtr, cipherText, 0, cipherTextLength);
                Console.WriteLine("Ciphertext: " + BitConverter.ToString(cipherText).Replace("-", ""));
            }

            // 分配解密后的明文的非托管内存
            IntPtr decryptedTextPtr = Marshal.AllocHGlobal(plainText.Length);

            // 设置 AES_CTR_DECRYPT 结构体
            AES_CTR_DECRYPT decryption = new AES_CTR_DECRYPT
            {
                CIPHER_TEXT = cipherTextPtr,
                KEY = keyPtr,
                IV = ivPtr,
                COUNTER = 0,
                CIPHER_TEXT_LENGTH = (UIntPtr)cipherTextLength,
                PLAIN_TEXT = decryptedTextPtr
            };

            // 执行解密
            int decryptedTextLength = AesIOInterop.AesCtrDecrypt(ref decryption);
            if (decryptedTextLength > 0)
            {
                Marshal.Copy(decryptedTextPtr, decryptedText, 0, decryptedTextLength);
                Console.WriteLine("Decrypted text: " + System.Text.Encoding.UTF8.GetString(decryptedText, 0, decryptedTextLength));
            }

            // 释放分配的非托管内存
            Marshal.FreeHGlobal(plainTextPtr);
            Marshal.FreeHGlobal(keyPtr);
            Marshal.FreeHGlobal(ivPtr);
            Marshal.FreeHGlobal(cipherTextPtr);
            Marshal.FreeHGlobal(decryptedTextPtr);
        }
    }
}
