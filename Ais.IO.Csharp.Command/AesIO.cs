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

            if (AsymmetricIOInterop.Generate(key128, key128.Length) == 0)
                Console.WriteLine("Generated Key (128 bits): " + BitConverter.ToString(key128).Replace("-", ""));
            if (AsymmetricIOInterop.Generate(key192, key192.Length) == 0)
                Console.WriteLine("Generated Key (192 bits): " + BitConverter.ToString(key192).Replace("-", ""));
            if (AsymmetricIOInterop.Generate(key256, key256.Length) == 0)
                Console.WriteLine("Generated Key (256 bits): " + BitConverter.ToString(key256).Replace("-", ""));
            if (AsymmetricIOInterop.Generate(iv, iv.Length) == 0)
                Console.WriteLine("Generated IV (128 bits): " + BitConverter.ToString(iv).Replace("-", ""));

            if (AsymmetricIOInterop.Import(inputKey, inputKey.Length, inputKeyBuffer, inputKeyBuffer.Length) == 0)
                Console.WriteLine("Generated Key from Input (256 bits): " + BitConverter.ToString(inputKeyBuffer).Replace("-", ""));
            if (AsymmetricIOInterop.Import(inputIV, inputIV.Length, inputIVBuffer, inputIVBuffer.Length) == 0)
                Console.WriteLine("Generated IV from Input (256 bits): " + BitConverter.ToString(inputIVBuffer).Replace("-", ""));
        }

        public static void CTR(string text, string key, long counter)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.Import(key);
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
                byte[] keyResult = aes.Import(key);
                byte[] ivResult = aes.Import(iv);
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
                byte[] keyResult = aes.Import(key);
                byte[] ivResult = aes.Import(iv);
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
                byte[] keyResult = aes.Import(key);
                byte[] ivResult = aes.Import(iv);
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
                byte[] keyResult = aes.Import(key);
                byte[] cipherText = aes.EcbEncrypt(plainText, keyResult, pkcs7Padding);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = aes.EcbDecrypt(cipherText, keyResult, pkcs7Padding);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void GCM(string text, string key, string nonce, string tag, string aad)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);
                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.Import(key);
                byte[] nonceResult = aes.Import(nonce);
                byte[] tagResult = aes.Import(tag);
                byte[] aadResult = aes.Import(aad);
                byte[] cipherText = aes.GcmEncrypt(plainText, keyResult, nonceResult, tagResult, aadResult);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = aes.GcmDecrypt(cipherText, keyResult, nonceResult, tagResult, aadResult);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void CCM(string text, string key, string nonce, string tag, string aad)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);
                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.Import(key);
                byte[] nonceResult = aes.Import(nonce);
                byte[] tagResult = aes.Import(tag);
                byte[] aadResult = aes.Import(aad);
                byte[] cipherText = aes.CcmEncrypt(plainText, keyResult, nonceResult, tagResult, aadResult);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = aes.CcmDecrypt(cipherText, keyResult, nonceResult, tagResult, aadResult);

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
                byte[] key1Result = aes.Import(key1);
                byte[] key2Result = aes.Import(key2);
                byte[] tweakResult = Encoding.UTF8.GetBytes(tweak);
                byte[] cipherText = aes.XtsEncrypt(plainText, key1Result, key2Result, tweakResult);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = aes.XtsDecrypt(cipherText, key1Result, key2Result, tweakResult);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void OCB(string text, string key, string nonce, string tag, string aad)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.Import(key);
                byte[] nonceResult = aes.Import(nonce);
                byte[] tagResult = aes.Import(tag);
                byte[] aadResult = aes.Import(aad);
                byte[] cipherText = aes.OcbEncrypt(plainText, keyResult, nonceResult, tagResult, aadResult);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = aes.OcbDecrypt(cipherText, keyResult, nonceResult, tagResult, aadResult);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void WRAP(string key, string wrapkey)
        {
            try
            {
                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Aes aes = new Aes();
                byte[] keyResult = aes.Import(key);
                byte[] wrapkeyResult = aes.Import(wrapkey);
                byte[] wrappedKey = aes.WrapEncrypt(keyResult, wrapkeyResult);

                Console.WriteLine(encoder.Encode<string>(wrappedKey));

                byte[] decryptedText = aes.WrapDecrypt(wrappedKey, wrapkeyResult);

                Console.WriteLine(Encoding.UTF8.GetString(decryptedText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }
    }
}
