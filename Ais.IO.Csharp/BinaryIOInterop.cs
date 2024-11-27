using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public static class BinaryIOInterop
    {
        private const string DllName = "..\\Ais.IO.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong NextLength(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CreateBinaryReader(string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void DestroyBinaryReader(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong GetReaderPosition(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong GetReaderLength(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadBoolean(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern byte ReadByte(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern sbyte ReadSByte(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern short ReadShort(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ushort ReadUShort(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ReadInt(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ReadUInt(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long ReadLong(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong ReadULong(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern float ReadFloat(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern double ReadDouble(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ReadBytes(IntPtr reader, byte[] buffer, ulong bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ReadString(IntPtr reader, StringBuilder buffer, ulong bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CreateBinaryWriter(string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void DestroyBinaryWriter(IntPtr writer);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong GetWriterPosition(IntPtr writer);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong GetWriterLength(IntPtr writer);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteBoolean(IntPtr writer, bool value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteByte(IntPtr writer, byte value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteSByte(IntPtr writer, sbyte value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteShort(IntPtr writer, short value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteUShort(IntPtr writer, ushort value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteInt(IntPtr writer, int value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteUInt(IntPtr writer, uint value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteLong(IntPtr writer, long value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteULong(IntPtr writer, ulong value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteFloat(IntPtr writer, float value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteDouble(IntPtr writer, double value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteBytes(IntPtr writer, byte[] bytes);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteString(IntPtr writer, string value);
    }
}
