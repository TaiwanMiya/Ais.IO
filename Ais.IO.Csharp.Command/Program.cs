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

                string text = "This is AES CTR Encryption/Decryption.";
                string key = "Key length must be 128, 192, 256";
                string iv = "IvMustBe128Size.";
                //AesIO.Generate();
                //AesIO.CTR(text);

                Aes aes = new Aes();
                byte[] keyResult = aes.ImportKey(key);
                byte[] ivResult = aes.ImportIV(iv);
                byte[] encryptResult = aes.CtrEncrypt(text, keyResult, ivResult);
                byte[] baseBuffer = new byte[2048];

                EncoderIOInterop.Base16Encode(encryptResult, baseBuffer, 2048);
                Console.WriteLine(Encoding.UTF8.GetString(baseBuffer));

                //StructT.GetStruct();
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