using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp.Command
{
    internal class DesIO
    {
        public static void CBC(string text, string key, string iv, bool pkcs5Padding)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Des des = new Des();
                byte[] keyResult = des.Import(key);
                byte[] ivResult = des.Import(iv);
                byte[] cipherText = des.CbcEncrypt(plainText, keyResult, ivResult, pkcs5Padding);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = des.CbcDecrypt(cipherText, keyResult, ivResult, pkcs5Padding);

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
                Des des = new Des();
                byte[] keyResult = des.Import(key);
                byte[] ivResult = des.Import(iv);
                byte[] cipherText = des.CfbEncrypt(plainText, keyResult, ivResult, segmentSize);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = des.CfbDecrypt(cipherText, keyResult, ivResult, segmentSize);

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
                Des des = new Des();
                byte[] keyResult = des.Import(key);
                byte[] ivResult = des.Import(iv);
                byte[] cipherText = des.OfbEncrypt(plainText, keyResult, ivResult);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = des.OfbDecrypt(cipherText, keyResult, ivResult);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void ECB(string text, string key, bool pkcs5Padding)
        {
            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes(text);

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Des des = new Des();
                byte[] keyResult = des.Import(key);
                byte[] cipherText = des.EcbEncrypt(plainText, keyResult, pkcs5Padding);

                Console.WriteLine(encoder.Encode<string>(cipherText));

                plainText = des.EcbDecrypt(cipherText, keyResult, pkcs5Padding);

                Console.WriteLine(Encoding.UTF8.GetString(plainText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void WRAP(string key, string wrapkey)
        {
            try
            {
                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Des des = new Des();
                byte[] keyResult = des.Import(key);
                byte[] wrapkeyResult = des.Import(wrapkey);
                byte[] wrappedKey = des.WrapEncrypt(keyResult, wrapkeyResult);

                Console.WriteLine(encoder.Encode<string>(wrappedKey));

                byte[] decryptedText = des.WrapDecrypt(wrappedKey, wrapkeyResult);

                Console.WriteLine(Encoding.UTF8.GetString(decryptedText));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }
    }
}
