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
        public static void BaseEncode(out byte[] outputB16, out byte[] outputB32, out byte[] outputB64, out byte[] outputB85)
        {
            byte[] inputB16 = Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base16 - Encode && Decode)");
            byte[] inputB32 = Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base32 - Encode && Decode)");
            byte[] inputB64 = Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base64 - Encode && Decode)");
            byte[] inputB85 = Encoding.UTF8.GetBytes("This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base85 - Encode && Decode)");
            outputB16 = new byte[2048];
            outputB32 = new byte[2048];
            outputB64 = new byte[2048];
            outputB85 = new byte[2048];
            int code16 = EncoderIOInterop.Base16Encode(inputB16, inputB16.LongLength, outputB16, 2048);
            int code32 = EncoderIOInterop.Base32Encode(inputB32, inputB32.LongLength, outputB32, 2048);
            int code64 = EncoderIOInterop.Base64Encode(inputB64, inputB64.LongLength, outputB64, 2048);
            int code85 = EncoderIOInterop.Base85Encode(inputB85, inputB85.LongLength, outputB85, 2048);
            string[] messageArray =
            [
                $"base16 encode [{code16}] = {Encoding.UTF8.GetString(outputB16)}",
                $"base32 encode [{code32}] = {Encoding.UTF8.GetString(outputB32)}",
                $"base64 encode [{code64}] = {Encoding.UTF8.GetString(outputB64)}",
                $"base85 encode [{code85}] = {Encoding.UTF8.GetString(outputB85)}",
            ];
            Console.WriteLine(string.Join("\n", messageArray));
        }

        public static void BaseDecode(byte[] inputB16, byte[] inputB32, byte[] inputB64, byte[] inputB85)
        {
            byte[] outputB16 = new byte[2048];
            byte[] outputB32 = new byte[2048];
            byte[] outputB64 = new byte[2048];
            byte[] outputB85 = new byte[2048];
            int code16 = EncoderIOInterop.Base16Decode(inputB16, inputB16.LongLength, outputB16, 2048);
            int code32 = EncoderIOInterop.Base32Decode(inputB32, inputB32.LongLength, outputB32, 2048);
            int code64 = EncoderIOInterop.Base64Decode(inputB64, inputB64.LongLength, outputB64, 2048);
            int code85 = EncoderIOInterop.Base85Decode(inputB85, inputB85.LongLength, outputB85, 2048);
            string[] messageArray =
            [
                $"base16 decode [{code16}] = {Encoding.UTF8.GetString(outputB16)}",
                $"base32 decode [{code32}] = {Encoding.UTF8.GetString(outputB32)}",
                $"base64 decode [{code64}] = {Encoding.UTF8.GetString(outputB64)}",
                $"base85 decode [{code85}] = {Encoding.UTF8.GetString(outputB85)}",
            ];
            Console.WriteLine(string.Join("\n", messageArray));
        }
    }
}
