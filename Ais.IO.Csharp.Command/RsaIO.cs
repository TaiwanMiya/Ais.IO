using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp.Command
{
    internal class RsaIO
    {
        public static void GetParamters(ulong size)
        {
            Rsa rsa = new Rsa();
            BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
            RsaParamters paramters = rsa.GenerateParamters(size);
            if (paramters == null)
                return;
            Console.WriteLine("Modulus (N):\n" + encoder.Encode<string>(paramters.N));
            Console.WriteLine("Public Exponent (E):\n" + encoder.Encode<string>(paramters.E));
            Console.WriteLine("Private Exponent (D):\n" + encoder.Encode<string>(paramters.D));
            Console.WriteLine("First Prime Factor (P):\n" + encoder.Encode<string>(paramters.P));
            Console.WriteLine("Second Prime Factor (Q):\n" + encoder.Encode<string>(paramters.Q));
            Console.WriteLine("First CRT Exponent (DP):\n" + encoder.Encode<string>(paramters.DP));
            Console.WriteLine("Second CRT Exponent (DQ):\n" + encoder.Encode<string>(paramters.DQ));
            Console.WriteLine("CRT Coefficient (QI):\n" + encoder.Encode<string>(paramters.QI));
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
