using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Reflection;
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

            if (AesIOInterop.GenerateKeyFromInput(inputKey, inputKey.Length, inputKeyBuffer, inputKeyBuffer.Length) == 0)
                Console.WriteLine("Generated Key from Input (256 bits): " + BitConverter.ToString(inputKeyBuffer).Replace("-", ""));
            if (AesIOInterop.GenerateIVFromInput(inputIV, inputIV.Length, inputIVBuffer, inputIVBuffer.Length) == 0)
                Console.WriteLine("Generated Key from Input (256 bits): " + BitConverter.ToString(inputIVBuffer).Replace("-", ""));
        }

        public static void CTR(string text, string key, long counter)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] cipherText = aes.CtrEncrypt(plainText, keyResult, counter);

                Console.WriteLine(BitConverter.ToString(cipherText).Replace("-", ""));

                plainText = aes.CtrDecrypt(cipherText, keyResult, counter);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void CBC(string text, string key, string iv, bool pkcs7Padding)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] ivResult = aes.ImportIV(iv);
                byte[] cipherText = aes.CbcEncrypt(plainText, keyResult, ivResult, pkcs7Padding);

                Console.WriteLine(BitConverter.ToString(cipherText).Replace("-", ""));

                plainText = aes.CbcDecrypt(cipherText, keyResult, ivResult, pkcs7Padding);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void CFB(string text, string key, string iv, SEGMENT_SIZE_OPTION segmentSize)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] ivResult = aes.ImportIV(iv);
                byte[] cipherText = aes.CfbEncrypt(plainText, keyResult, ivResult, segmentSize);

                Console.WriteLine(BitConverter.ToString(cipherText).Replace("-", ""));

                plainText = aes.CfbDecrypt(cipherText, keyResult, ivResult, segmentSize);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }
    }
}
