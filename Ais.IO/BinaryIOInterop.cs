using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO
{
    public static class BinaryIOInterop
    {
        private const string DllName = "Ais.IO.Source.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int NextLength(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern nint CreateBinaryReader(string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void DestroyBinaryReader(nint reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long GetReaderPosition(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long GetReaderLength(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadBoolean(nint reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern byte ReadByte(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern sbyte ReadSByte(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern short ReadShort(nint reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ushort ReadUShort(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ReadInt(nint reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ReadUInt(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long ReadLong(nint reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong ReadULong(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern float ReadFloat(nint reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern double ReadDouble(nint reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ReadBytes(nint reader, byte[] buffer, int length);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ReadString(nint reader, StringBuilder buffer, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern nint CreateBinaryWriter(string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void DestroyBinaryWriter(nint writer);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long GetWriterPosition(IntPtr writer);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long GetWriterLength(IntPtr writer);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteBoolean(nint writer, bool value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteByte(IntPtr writer, byte value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteSByte(IntPtr writer, sbyte value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteShort(nint writer, short value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteUShort(IntPtr writer, ushort value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteInt(nint writer, int value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteUInt(IntPtr writer, uint value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteLong(nint writer, long value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteULong(IntPtr writer, ulong value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteFloat(nint writer, float value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteDouble(nint writer, double value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteBytes(nint writer, byte[] bytes, int length);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteString(nint writer, string value);
    }
}
