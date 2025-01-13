using Ais.IO.Csharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp.Command
{
    internal class EncoderIO
    {
        public static void BaseEncode(out string outputB10, out string outputB16, out string outputB32, out string outputB58, out string outputB62, out string outputB64, out string outputB85, out string outputB91)
        {
            BaseEncoding encoder = new BaseEncoding();
            outputB10 = encoder.Encode(Encoding.UTF8.GetBytes("ABCD"), EncodingType.Base10);
            outputB16 = encoder.Encode(Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base16 - Encode && Decode)"), EncodingType.Base16);
            outputB32 = encoder.Encode(Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base32 - Encode && Decode)"), EncodingType.Base32);
            outputB58 = encoder.Encode(Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base58 - Encode && Decode)"), EncodingType.Base58);
            outputB62 = encoder.Encode(Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base62 - Encode && Decode)"), EncodingType.Base62);
            outputB64 = encoder.Encode(Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base64 - Encode && Decode)"), EncodingType.Base64);
            outputB85 = encoder.Encode(Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base85 - Encode && Decode)"), EncodingType.Base85);
            outputB91 = encoder.Encode(Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base91 - Encode && Decode)"), EncodingType.Base91);
            string[] messageArray =
            [
                $"base10 encode [{outputB10.LongCount()}] = {outputB10}",
                $"base16 encode [{outputB16.LongCount()}] = {outputB16}",
                $"base32 encode [{outputB32.LongCount()}] = {outputB32}",
                $"base58 encode [{outputB58.LongCount()}] = {outputB58}",
                $"base62 encode [{outputB62.LongCount()}] = {outputB62}",
                $"base64 encode [{outputB64.LongCount()}] = {outputB64}",
                $"base85 encode [{outputB85.LongCount()}] = {outputB85}",
                $"base91 encode [{outputB91.LongCount()}] = {outputB91}",
            ];
            Console.WriteLine(string.Join("\n", messageArray));
        }

        public static void BaseDecode(string inputB10, string inputB16, string inputB32, string inputB58, string inputB62, string inputB64, string inputB85, string inputB91)
        {
            BaseEncoding encoder = new BaseEncoding();
            byte[] outputB10 = encoder.Decode(inputB10, EncodingType.Base10);
            byte[] outputB16 = encoder.Decode(inputB16, EncodingType.Base16);
            byte[] outputB32 = encoder.Decode(inputB32, EncodingType.Base32);
            byte[] outputB58 = encoder.Decode(inputB58, EncodingType.Base58);
            byte[] outputB62 = encoder.Decode(inputB62, EncodingType.Base62);
            byte[] outputB64 = encoder.Decode(inputB64, EncodingType.Base64);
            byte[] outputB85 = encoder.Decode(inputB85, EncodingType.Base85);
            byte[] outputB91 = encoder.Decode(inputB91, EncodingType.Base91);
            string[] messageArray =
            [
                $"base10 decode [{outputB10.LongLength}] = {Encoding.UTF8.GetString(outputB10)}",
                $"base16 decode [{outputB16.LongLength}] = {Encoding.UTF8.GetString(outputB16)}",
                $"base32 decode [{outputB32.LongLength}] = {Encoding.UTF8.GetString(outputB32)}",
                $"base58 decode [{outputB58.LongLength}] = {Encoding.UTF8.GetString(outputB58)}",
                $"base62 decode [{outputB62.LongLength}] = {Encoding.UTF8.GetString(outputB62)}",
                $"base64 decode [{outputB64.LongLength}] = {Encoding.UTF8.GetString(outputB64)}",
                $"base85 decode [{outputB85.LongLength}] = {Encoding.UTF8.GetString(outputB85)}",
                $"base91 decode [{outputB91.LongLength}] = {Encoding.UTF8.GetString(outputB91)}",
            ];
            Console.WriteLine(string.Join("\n", messageArray));
        }
    }
}
