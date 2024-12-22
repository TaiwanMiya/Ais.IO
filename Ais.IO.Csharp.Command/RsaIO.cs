using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp.Command
{
    internal class RsaIO
    {
        public static void GetParamters(int size)
        {
            Rsa rsa = new Rsa();
            rsa.GenerateParamters(size);
        }

        public static void GeneratePEM(int size)
        {
            Rsa rsa = new Rsa();
            BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
            byte[] publicKey = [];
            byte[] privateKey = [];
            rsa.Generate(size, ASYMMETRIC_KEY_FORMAT.ASYMMETRIC_KEY_PEM, ref publicKey, ref privateKey);

            if (publicKey.Length == 0 || privateKey.Length == 0)
                return;
            Console.WriteLine($"[Public Key ({size} PEM)]\n" + Encoding.UTF8.GetString(publicKey));
            Console.WriteLine($"[Private Key ({size} PEM)]\n" + Encoding.UTF8.GetString(privateKey));
        }

        public static void GenerateDER(int size)
        {
            Rsa rsa = new Rsa();
            BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
            byte[] publicKey = [];
            byte[] privateKey = [];
            rsa.Generate(size, ASYMMETRIC_KEY_FORMAT.ASYMMETRIC_KEY_DER, ref publicKey, ref privateKey);
            
            if (publicKey.Length == 0 || privateKey.Length == 0)
                return;
            Console.WriteLine($"[Public Key ({size} DER)]\n" + encoder.Encode<string>(publicKey));
            Console.WriteLine($"[Private Key ({size} DER)]\n" + encoder.Encode<string>(privateKey));
        }
    }
}
