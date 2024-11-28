using Ais.IO.Csharp;
using System.Text;

namespace Ais.IO.Command
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            try
            {
                //WriteRelease();
                //ReadRelease();
                BaseEncode(out byte[] b16, out byte[] b32, out byte[] b64, out byte[] b85);
                BaseDecode(b16, b32, b64, b85);
                Console.WriteLine("Press Any Key To Continue...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        private static void WriteRelease()
        {
            IntPtr writer = BinaryIOInterop.CreateBinaryWriter("test.bin");
            BinaryIOInterop.WriteBoolean(writer, true);
            BinaryIOInterop.WriteShort(writer, 0x7FFF);
            BinaryIOInterop.WriteInt(writer, 0x7FFFFFFF);
            BinaryIOInterop.WriteLong(writer, 0x7FFFFFFFFFFFFFFF);
            BinaryIOInterop.WriteByte(writer, 255);
            BinaryIOInterop.WriteSByte(writer, -128);
            BinaryIOInterop.WriteUShort(writer, 65535);
            BinaryIOInterop.WriteUInt(writer, 4294967295);
            BinaryIOInterop.WriteULong(writer, 18446744073709551615);
            BinaryIOInterop.WriteFloat(writer, 3.1415927F);
            BinaryIOInterop.WriteDouble(writer, 3.141592653589793D);
            BinaryIOInterop.WriteString(writer, "This is Ais.IO Release Function String.");

            byte[] byteArray = Encoding.UTF8.GetBytes("This is Ais.IO Release Function Byte Array.");
            BinaryIOInterop.WriteBytes(writer, byteArray);
            BinaryIOInterop.DestroyBinaryWriter(writer);
        }

        private static void ReadRelease()
        {
            IntPtr reader = BinaryIOInterop.CreateBinaryReader("test.bin");

            while (BinaryIOInterop.GetReaderPosition(reader) < BinaryIOInterop.GetReaderLength(reader))
            {
                var @bool = BinaryIOInterop.ReadBoolean(reader);
                var @short = BinaryIOInterop.ReadShort(reader);
                var @int = BinaryIOInterop.ReadInt(reader);
                var @long = BinaryIOInterop.ReadLong(reader);
                var @byte = BinaryIOInterop.ReadByte(reader);
                var @sbyte = BinaryIOInterop.ReadSByte(reader);
                var @ushort = BinaryIOInterop.ReadUShort(reader);
                var @uint = BinaryIOInterop.ReadUInt(reader);
                var @ulong = BinaryIOInterop.ReadULong(reader);
                var @float = BinaryIOInterop.ReadFloat(reader);
                var @double = BinaryIOInterop.ReadDouble(reader);

                ulong stringLength = BinaryIOInterop.NextLength(reader);
                StringBuilder stringBuffer = new StringBuilder((int)stringLength);
                BinaryIOInterop.ReadString(reader, stringBuffer, (uint)stringLength);

                ulong bytesLength = BinaryIOInterop.NextLength(reader);
                byte[] bytesBuffer = new byte[bytesLength];
                BinaryIOInterop.ReadBytes(reader, bytesBuffer, bytesLength);

                string[] messageArray =
                [
                    $"bool = {@bool}",
                    $"short = {@short}",
                    $"int = {@int}",
                    $"long = {@long}",
                    $"byte = {@byte}",
                    $"sbyte = {@sbyte}",
                    $"ushort = {@ushort}",
                    $"uint = {@uint}",
                    $"ulong = {@ulong}",
                    $"float = {@float}",
                    $"double = {@double}",
                    $"string = {stringBuffer}",
                    $"bytes = {Encoding.UTF8.GetString(bytesBuffer)}",
                ];
                Console.WriteLine(string.Join("\n", messageArray));
            }
            BinaryIOInterop.DestroyBinaryReader(reader);
        }

        private static void BaseEncode(out byte[] outputB16, out byte[] outputB32, out byte[] outputB64, out byte[] outputB85)
        {
            byte[] inputB16 = Encoding.UTF8.GetBytes("這是 Base16 編碼，而此 Base16 使用 Ais.IO 來解碼。");
            byte[] inputB32 = Encoding.UTF8.GetBytes("這是 Base32 編碼，而此 Base32 使用 Ais.IO 來解碼。");
            byte[] inputB64 = Encoding.UTF8.GetBytes("這是 Base64 編碼，而此 Base64 使用 Ais.IO 來解碼。");
            byte[] inputB85 = Encoding.UTF8.GetBytes("這是 Base85 編碼，而此 Base85 使用 Ais.IO 來解碼。");
            outputB16 = new byte[2048];
            outputB32 = new byte[2048];
            outputB64 = new byte[2048];
            outputB85 = new byte[2048];
            int code16 = BinaryIOInterop.Base16Encode(inputB16, outputB16, 2048);
            int code32 = BinaryIOInterop.Base32Encode(inputB32, outputB32, 2048);
            int code64 = BinaryIOInterop.Base64Encode(inputB64, outputB64, 2048);
            int code85 = BinaryIOInterop.Base85Encode(inputB85, outputB85, 2048);
            string[] messageArray =
            [
                $"base16 encode [{code16}] = {Encoding.UTF8.GetString(outputB16)}",
                $"base32 encode [{code32}] = {Encoding.UTF8.GetString(outputB32)}",
                $"base64 encode [{code64}] = {Encoding.UTF8.GetString(outputB64)}",
                $"base85 encode [{code85}] = {Encoding.UTF8.GetString(outputB85)}",
            ];
            Console.WriteLine(string.Join("\n", messageArray));
        }

        private static void BaseDecode(byte[] inputB16, byte[] inputB32, byte[] inputB64, byte[] inputB85)
        {
            byte[] outputB16 = new byte[2048];
            byte[] outputB32 = new byte[2048];
            byte[] outputB64 = new byte[2048];
            byte[] outputB85 = new byte[2048];
            int code16 = BinaryIOInterop.Base16Decode(inputB16, outputB16, 2048);
            int code32 = BinaryIOInterop.Base32Decode(inputB32, outputB32, 2048);
            int code64 = BinaryIOInterop.Base64Decode(inputB64, outputB64, 2048);
            int code85 = BinaryIOInterop.Base85Decode(inputB85, outputB85, 2048);
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