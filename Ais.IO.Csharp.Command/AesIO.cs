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

            if (AesIOInterop.ImportKey(inputKey, inputKey.Length, inputKeyBuffer, inputKeyBuffer.Length) == 0)
                Console.WriteLine("Generated Key from Input (256 bits): " + BitConverter.ToString(inputKeyBuffer).Replace("-", ""));
            if (AesIOInterop.ImportIV(inputIV, inputIV.Length, inputIVBuffer, inputIVBuffer.Length) == 0)
                Console.WriteLine("Generated Key from Input (256 bits): " + BitConverter.ToString(inputIVBuffer).Replace("-", ""));
        }

        public static void CTR(string text, string key, long counter)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] cipherText = aes.CtrEncrypt(plainText, keyResult, counter);

                Console.WriteLine(encoder.Encode<string>(cipherText));

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

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] ivResult = aes.ImportIV(iv);
                byte[] cipherText = aes.CbcEncrypt(plainText, keyResult, ivResult, pkcs7Padding);

                Console.WriteLine(encoder.Encode<string>(cipherText));

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

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] ivResult = aes.ImportIV(iv);
                byte[] cipherText = aes.CfbEncrypt(plainText, keyResult, ivResult, segmentSize);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = aes.CfbDecrypt(cipherText, keyResult, ivResult, segmentSize);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void OFB(string text, string key, string iv)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] ivResult = aes.ImportIV(iv);
                byte[] cipherText = aes.OfbEncrypt(plainText, keyResult, ivResult);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = aes.OfbDecrypt(cipherText, keyResult, ivResult);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void ECB(string text, string key, bool pkcs7Padding)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] cipherText = aes.EcbEncrypt(plainText, keyResult, pkcs7Padding);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = aes.EcbDecrypt(cipherText, keyResult, pkcs7Padding);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void GCM(string text, string key, string iv, string tag)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);
                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] ivResult = aes.ImportIV(iv);
                byte[] tagResult = aes.ImportTag(tag);
                byte[] cipherText = aes.GcmEncrypt(plainText, keyResult, ivResult, tagResult);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = aes.GcmDecrypt(cipherText, keyResult, ivResult, tagResult);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void CCM(string text, string key, string iv, string tag, string aad)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);
                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] ivResult = aes.ImportIV(iv);
                byte[] tagResult = aes.ImportTag(tag);
                byte[] aadResult = aes.ImportAad(aad);
                byte[] cipherText = aes.CcmEncrypt(plainText, keyResult, ivResult, tagResult, aadResult);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = aes.CcmDecrypt(cipherText, keyResult, ivResult, tagResult, aadResult);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void XTS(string text, string key1, string key2, string tweak)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] key1Result = aes.ImportKey(key1);
                byte[] key2Result = aes.ImportKey(key2);
                byte[] tweakResult = Encoding.UTF8.GetBytes(tweak);
                byte[] cipherText = aes.XtsEncrypt(plainText, key1Result, key2Result, tweakResult);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                byte[] decryptedText = aes.XtsDecrypt(cipherText, key1Result, key2Result, tweakResult);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }
    }
}
