using System;
using System.Collections.Generic;
using System.Linq;
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

            if (AesIOInterop.GenerateKeyFromInput(inputKey, inputKeyBuffer, inputKeyBuffer.Length) == 0)
                Console.WriteLine("Generated Key from Input (256 bits): " + BitConverter.ToString(inputKeyBuffer).Replace("-", ""));
            if (AesIOInterop.GenerateIVFromInput(inputIV, inputIVBuffer, inputIVBuffer.Length) == 0)
                Console.WriteLine("Generated Key from Input (256 bits): " + BitConverter.ToString(inputIVBuffer).Replace("-", ""));
        }
    }
}
