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
                WriteRelease();
                ReadRelease();
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
    }
}