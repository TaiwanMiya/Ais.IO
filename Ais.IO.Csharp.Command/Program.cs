using Ais.IO.Csharp;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Ais.IO.Csharp.Command
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            try
            {
                Stopwatch sw = new Stopwatch();

                sw.Start();
                BinaryIO.WriteRelease();
                BinaryIO.ReadRelease();
                //EncoderIO.BaseEncode(out byte[] b16, out byte[] b32, out byte[] b64, out byte[] b85);
                //EncoderIO.BaseDecode(b16, b32, b64, b85);

                //string text = string.Empty;
                //string key = "Key length must be 128, 192, 256";
                //string iv = "IvMustBe128Size.";

                //int cryptionCount = 100;
                //for (int i = 0; i < cryptionCount; i++)
                //{
                //    text = "This is AES CTR Encryption/Decryption.";
                //    AesIO.CTR(text, key, 1);

                //    text = "This is AES CBC Encryption/Decryption.";
                //    AesIO.CBC(text, key, iv, true);

                //    text = "This is AES CFB Encryption/Decryption.";
                //    AesIO.CFB(text, key, iv, SEGMENT_SIZE_OPTION.SEGMENT_128_BIT);

                //    text = "This is AES OFB Encryption/Decryption.";
                //    AesIO.OFB(text, key, iv);

                //    text = "This is AES ECB Encryption/Decryption.";
                //    AesIO.ECB(text, key, true);
                //}

                //text = "This is AES CTR Encryption/Decryption.";
                //AesIO.CTR(text, key, 1);

                //text = "This is AES CBC Encryption/Decryption.";
                //AesIO.CBC(text, key, iv, true);

                //text = "This is AES CFB Encryption/Decryption.";
                //AesIO.CFB(text, key, iv, SEGMENT_SIZE_OPTION.SEGMENT_128_BIT);

                //text = "This is AES OFB Encryption/Decryption.";
                //AesIO.OFB(text, key, iv);

                //text = "This is AES ECB Encryption/Decryption.";
                //AesIO.ECB(text, key, true);

                sw.Stop();
                Console.WriteLine($"Milli Seconds: {sw.ElapsedMilliseconds}");
                Console.WriteLine("Press Any Key To Continue...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }
    }
}