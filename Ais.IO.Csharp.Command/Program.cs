using Ais.IO.Csharp;
using System.Diagnostics;
using System.Linq;
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
                //BinaryIO.WriteRelease();
                //BinaryIO.AppendRelease();
                //BinaryIO.InsertRelease();
                //BinaryIO.GetIndex();
                //BinaryIO.ReadRelease();
                //EncoderIO.BaseEncode(out byte[] b16, out byte[] b32, out byte[] b64, out byte[] b85);
                //EncoderIO.BaseDecode(b16, b32, b64, b85);

                //AesIO.Generate();

                //StartAes(1);

                //StartDes(1);

                StartHash(1);

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

        private static void StartAes(int range)
        {
            string text = string.Empty;
            string key = "Key length must be 128, 192, 256";
            string iv = "IvMustBe128Size.";
            string tag = "TagMustBe128Size";
            string aad = "Additional Authenticated Data (AAD) can be of any length";
            string key2 = "Secondary Key for AES-XTS Tweak.";
            string tweak = "SectorNumber0001";
            string kek = "This is AES WRAP, 128, 192, 256.";
            string nonce = "Nonce12bytes";

            for (int i = 0; i < range; i++)
            {
                text = "This is AES CTR Encryption/Decryption.";
                AesIO.CTR(text, key, 1);

                text = "This is AES CBC Encryption/Decryption.";
                AesIO.CBC(text, key, iv, true);

                text = "This is AES CFB Encryption/Decryption.";
                AesIO.CFB(text, key, iv, SEGMENT_SIZE_OPTION.SEGMENT_128_BIT);

                text = "This is AES OFB Encryption/Decryption.";
                AesIO.OFB(text, key, iv);

                text = "This is AES ECB Encryption/Decryption.";
                AesIO.ECB(text, key, true);

                text = "This is AES GCM Encryption/Decryption.";
                AesIO.GCM(text, key, nonce, tag, aad);

                text = "This is AES CCM Encryption/Decryption.";
                AesIO.CCM(text, key, nonce, tag, aad);

                text = "This is AES XTS Encryption/Decryption.";
                AesIO.XTS(text, key, key2, tweak);

                text = "This is AES OCB Encryption/Decryption.";
                AesIO.OCB(text, key, nonce, tag, aad);

                AesIO.WRAP(key, kek);
            }
        }

        private static void StartDes(int range)
        {
            string text = string.Empty;
            string key = "Key Must Be 128,192 Size";
            string kek = "WRAP Key 128 192 by DES.";
            string iv = "Iv8Bytes";

            for (int i = 0; i < range; i++)
            {
                text = "This is DES CBC Encryption/Decryption.";
                DesIO.CBC(text, key, iv, true);

                text = "This is DES CFB Encryption/Decryption.";
                DesIO.CFB(text, key, iv, SEGMENT_SIZE_OPTION.SEGMENT_64_BIT);

                text = "This is DES OFB Encryption/Decryption.";
                DesIO.OFB(text, key, iv);

                text = "This is DES ECB Encryption/Decryption.";
                DesIO.ECB(text, key, true);

                DesIO.WRAP(key, kek);
            }
        }

        private static void StartHash(int range)
        {
            string text = string.Empty;
            string salt = string.Empty;
            Hash hash = new Hash();

            for (int i = 0; i < range; i++)

            {
                HASH_TYPE[] types = (HASH_TYPE[]) Enum.GetValues(typeof(HASH_TYPE));
                foreach (HASH_TYPE type in types)
                {
                    string display = new string(type.ToString().TakeLast(type.ToString().Length - 5).ToArray()).Replace("_", " ");
                    text = $"This is HASH {type} Calculation.";
                    salt = $"This is HASH {type} Salt..";
                    Console.WriteLine(text);
                    HashIO.Run(text, salt, type, SALT_SEQUENCE.SALT_MIDDLE);
                }
            }
        }
    }
}