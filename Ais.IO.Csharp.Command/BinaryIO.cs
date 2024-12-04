using Ais.IO.Csharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp.Command
{
    internal class BinaryIO
    {
        public static void WriteRelease()
        {
            Binary binary = new Binary("test.bin");
            binary.Write<bool>(true);
            binary.Write<short>(0x7FFF);
            binary.Write<int>(0x7FFFFFFF);
            binary.Write<long>(0x7FFFFFFFFFFFFFFF);
            binary.Write<byte>(255);
            binary.Write<sbyte>(-128);
            binary.Write<ushort>(65535);
            binary.Write<uint>(4294967295);
            binary.Write<ulong>(18446744073709551615);
            binary.Write<float>(3.1415927F);
            binary.Write<double>(3.141592653589793D);
            binary.Write<byte[]>(Encoding.UTF8.GetBytes("This is Ais.IO Release Function Byte Array."));
            binary.Write<string>("This is Ais.IO Release Function String.");
            binary.Close();
        }

        public static void AppendRelease()
        {
            Binary binary = new Binary("test.bin");
            binary.Append<bool>(true);
            binary.Append<byte>(255);
            binary.Append<sbyte>(-128);
            binary.Append<short>(0x7FFF);
            binary.Append<ushort>(65535);
            binary.Append<int>(0x7FFFFFFF);
            binary.Append<uint>(4294967295);
            binary.Append<long>(0x7FFFFFFFFFFFFFFF);
            binary.Append<ulong>(18446744073709551615);
            binary.Append<float>(3.1415927F);
            binary.Append<double>(3.141592653589793D);
            binary.Append<byte[]>(Encoding.UTF8.GetBytes("This is Ais.IO Release Function Byte Array."));
            binary.Append<string>("This is Ais.IO Release Function String.");
            binary.Close();
        }

        public static void ReadRelease()
        {
            Binary binary = new Binary("test.bin");
            string message = string.Empty;
            while (binary.ReaderPosition < binary.ReaderLength)
            {
                object result = binary.Read();
                if (result.GetType() == typeof(byte[]))
                    message += $"{result.GetType()} = {Encoding.UTF8.GetString((byte[])result)}";
                else
                    message += $"{result.GetType()} = {result}";
                message += Environment.NewLine;
            }
            binary.Close();
            Console.WriteLine(message);
        }
    }
}
