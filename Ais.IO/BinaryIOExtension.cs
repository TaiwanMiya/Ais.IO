using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO
{
    public static class FileExtension
    {
        public static FileInfo ToFile(this string filePath) => new(filePath);
        public static DirectoryInfo ToDirectory(this string directoryPath) => new(directoryPath);
    }

    public static class BinaryReaderExtension
    {
        public static nint Open(this FileInfo file) => BinaryIOInterop.CreateBinaryReader(file.FullName);
        public static nint Open(this string file) => BinaryIOInterop.CreateBinaryReader(file);
        public static long Position(nint reader) => BinaryIOInterop.GetReaderPosition(reader);
        public static long Length(nint reader) => BinaryIOInterop.GetReaderLength(reader);
        public static void Close(nint reader) => BinaryIOInterop.DestroyBinaryReader(reader);
        public static bool ReadBoolean(nint reader) => BinaryIOInterop.ReadBoolean(reader);
        public static byte ReadByte(nint reader) => BinaryIOInterop.ReadByte(reader);
        public static sbyte ReadSByte(nint reader) => BinaryIOInterop.ReadSByte(reader);
        public static short ReadShort(nint reader) => BinaryIOInterop.ReadShort(reader);
        public static ushort ReadUShort(nint reader) => BinaryIOInterop.ReadUShort(reader);
        public static int ReadInt(nint reader) => BinaryIOInterop.ReadInt(reader);
        public static uint ReadUInt(nint reader) => BinaryIOInterop.ReadUInt(reader);
        public static long ReadLong(nint reader) => BinaryIOInterop.ReadLong(reader);
        public static ulong ReadULong(nint reader) => BinaryIOInterop.ReadULong(reader);
        public static float ReadFloat(nint reader) => BinaryIOInterop.ReadFloat(reader);
        public static double ReadDouble(nint reader) => BinaryIOInterop.ReadDouble(reader);
        public static byte[] ReadBytes(nint reader, int maxLength)
        {
            byte[] buffer = new byte[maxLength];
            BinaryIOInterop.ReadBytes(reader, buffer, maxLength);
            return buffer;
        }
        public static string ReadString(nint reader, int maxLength)
        {
            StringBuilder buffer = new StringBuilder();
            BinaryIOInterop.ReadString(reader, buffer, maxLength);
            return buffer.ToString();
        }
    }

    public static class BinaryWriterExtension
    {
        public static nint Open(this FileInfo file) => BinaryIOInterop.CreateBinaryWriter(file.FullName);
        public static nint Open(this string file) => BinaryIOInterop.CreateBinaryWriter(file);
        public static long Position(nint writer) => BinaryIOInterop.GetWriterPosition(writer);
        public static long Length(nint writer) => BinaryIOInterop.GetWriterLength(writer);
        public static void Close(nint writer) => BinaryIOInterop.DestroyBinaryWriter(writer);
        public static void Write(nint writer, bool value) => BinaryIOInterop.WriteBoolean(writer, value);
        public static void Write(nint writer, byte value) => BinaryIOInterop.WriteByte(writer, value);
        public static void Write(nint writer, sbyte value) => BinaryIOInterop.WriteSByte(writer, value);
        public static void Write(nint writer, short value) => BinaryIOInterop.WriteShort(writer, value);
        public static void Write(nint writer, ushort value) => BinaryIOInterop.WriteUShort(writer, value);
        public static void Write(nint writer, int value) => BinaryIOInterop.WriteInt(writer, value);
        public static void Write(nint writer, uint value) => BinaryIOInterop.WriteUInt(writer, value);
        public static void Write(nint writer, long value) => BinaryIOInterop.WriteLong(writer, value);
        public static void Write(nint writer, ulong value) => BinaryIOInterop.WriteULong(writer, value);
        public static void Write(nint writer, float value) => BinaryIOInterop.WriteFloat(writer, value);
        public static void Write(nint writer, double value) => BinaryIOInterop.WriteDouble(writer, value);
        public static void Write(nint writer, byte[] value) => BinaryIOInterop.WriteBytes(writer, value, value.Length);
        public static void Write(nint writer, string value) => BinaryIOInterop.WriteString(writer, value);
    }
}
