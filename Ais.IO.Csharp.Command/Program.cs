using Ais.IO.Csharp;
using System.Text;

namespace Ais.IO.Csharp.Command
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            try
            {
                //BinaryIO.WriteRelease();
                //BinaryIO.ReadRelease();
                //EncoderIO.BaseEncode(out byte[] b16, out byte[] b32, out byte[] b64, out byte[] b85);
                //EncoderIO.BaseDecode(b16, b32, b64, b85);

                string text = string.Empty;
                string key = "Key length must be 128, 192, 256";
                string iv = "IvMustBe128Size.";

                text = "This is AES CTR Encryption/Decryption.";
                AesIO.CTR(text, key, 1);

                text = "This is AES CBC Encryption/Decryption.";
                AesIO.CBC(text, key, iv, true);

                text = "This is AES CFB Encryption/Decryption.";
                AesIO.CFB(text, key, iv, SEGMENT_SIZE_OPTION.SEGMENT_128_BIT);

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