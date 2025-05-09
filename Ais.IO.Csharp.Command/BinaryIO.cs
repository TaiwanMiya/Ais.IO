﻿using Ais.IO.Csharp;
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
            Csharp.BinaryIO binary = new Csharp.BinaryIO("test.bin");
            binary.Write<bool>(true);
            binary.Write<byte>(0xFF);
            binary.Write<sbyte>(0x7F);
            binary.Write<short>(0x7FFF);
            binary.Write<ushort>(0xFFFF);
            binary.Write<int>(0x7FFFFFFF);
            binary.Write<uint>(0XFFFFFFFF);
            binary.Write<long>(0x7FFFFFFFFFFFFFFF);
            binary.Write<ulong>(0xFFFFFFFFFFFFFFFF);
            binary.Write<float>(3.1415927F);
            binary.Write<double>(3.141592653589793D);
            binary.Write<byte[]>(Encoding.UTF8.GetBytes("This is Ais.IO Release Function Byte Array."));
            binary.Write<string>("This is Ais.IO Release Function String.");
            binary.Close();
        }

        public static void AppendRelease()
        {
            Csharp.BinaryIO binary = new Csharp.BinaryIO("test.bin");
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

        public static void InsertRelease()
        {
            Csharp.BinaryIO binary = new Csharp.BinaryIO("test.bin");
            binary.Insert<bool>(true, 0);
            binary.Insert<byte>(255, 0);
            binary.Insert<sbyte>(-128, 0);
            binary.Insert<short>(0x7FFF, 0);
            binary.Insert<ushort>(65535, 0);
            binary.Insert<int>(0x7FFFFFFF, 0);
            binary.Insert<uint>(4294967295, 0);
            binary.Insert<long>(0x7FFFFFFFFFFFFFFF, 0);
            binary.Insert<ulong>(18446744073709551615, 0);
            binary.Insert<float>(3.1415927F, 0);
            binary.Insert<double>(3.141592653589793D, 0);
            binary.Insert<byte[]>(Encoding.UTF8.GetBytes("This is Ais.IO Release Function Byte Array."), 0);
            binary.Insert<string>("This is Ais.IO Release Function String.", 0);
            binary.Close();
        }

        public static void ReadRelease()
        {
            Csharp.BinaryIO binary = new Csharp.BinaryIO("test.bin");
            string message = string.Empty;
            while (binary.ReaderPosition < binary.ReaderLength)
            {
                object result = binary.Read();
                if (result == null)
                    message += $"System.Nullable = NULL";
                else if (result.GetType() == typeof(byte[]))
                    message += $"{result.GetType()} = {Encoding.UTF8.GetString((byte[])result)}";
                else
                    message += $"{result.GetType()} = {result}";
                message += Environment.NewLine;
            }
            binary.Close();
            Console.WriteLine(message);
        }

        public static void GetIndex()
        {
            Csharp.BinaryIO binary = new Csharp.BinaryIO("test.bin");
            BINARYIO_INDICES[] indexes = binary.GetAllIndices();
            ulong count = 0;
            foreach (BINARYIO_INDICES index in indexes)
            {
                Console.WriteLine($"{count}. pos:{index.POSITION}, type:{index.TYPE}, len:{index.LENGTH}");
                count++;
            }
            Console.WriteLine($"Total Count: {indexes.Length}");
            binary.Close();

            ReadIndex(indexes);
            RemoveIndex(indexes);
        }

        public static void RemoveIndex(BINARYIO_INDICES[] indexes)
        {
            Csharp.BinaryIO binary = new Csharp.BinaryIO("test.bin");
            foreach (BINARYIO_INDICES index in indexes)
                binary.RemoveIndex(index);
            binary.Close();
        }

        public static void ReadIndex(BINARYIO_INDICES[] indexes)
        {
            Csharp.BinaryIO binary = new Csharp.BinaryIO("test.bin");
            string message = string.Empty;
            foreach (BINARYIO_INDICES index in indexes)
            {
                object result = binary.Read((long)index.POSITION);
                if (result == null)
                    message += $"System.Nullable = NULL";
                else if (result.GetType() == typeof(byte[]))
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
