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

        #region BinaryIO.h
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong NextLength(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern BINARYIO_TYPE ReadType(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetAllIndices(IntPtr reader, out ulong count);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void RemoveIndex(IntPtr reader, string filePath, BINARYIO_INDICES index);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void FreeIndexArray(IntPtr indices);
        #endregion

        #region BinaryReaderIO.h
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CreateBinaryReader(string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void DestroyBinaryReader(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong GetReaderPosition(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong GetReaderLength(IntPtr reader);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadBoolean(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern byte ReadByte(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern sbyte ReadSByte(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern short ReadShort(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ushort ReadUShort(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ReadInt(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ReadUInt(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long ReadLong(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong ReadULong(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern float ReadFloat(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern double ReadDouble(IntPtr reader, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ReadBytes(IntPtr reader, byte[] buffer, ulong bufferSize, long position = -1);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ReadString(IntPtr reader, StringBuilder buffer, ulong bufferSize, long position = -1);
        #endregion

        #region BinaryWriterIO.h
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
        public static extern void WriteBytes(IntPtr writer, byte[] bytes, long length);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void WriteString(IntPtr writer, string value);
        #endregion

        #region BinaryAppenderIO.h
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CreateBinaryAppender(string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void DestroyBinaryAppender(IntPtr writer);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong GetAppenderPosition(IntPtr writer);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong GetAppenderLength(IntPtr writer);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendBoolean(IntPtr appender, bool value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendByte(IntPtr appender, byte value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendSByte(IntPtr appender, sbyte value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendShort(IntPtr appender, short value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendUShort(IntPtr appender, ushort value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendInt(IntPtr appender, int value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendUInt(IntPtr appender, uint value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendLong(IntPtr appender, long value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendULong(IntPtr appender, ulong value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendFloat(IntPtr appender, float value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendDouble(IntPtr appender, double value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendBytes(IntPtr appender, byte[] bytes, long length);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void AppendString(IntPtr appender, string value);
        #endregion

        #region BinaryInserterIO.h
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CreateBinaryInserter(string filePath);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void DestroyBinaryInserter(IntPtr inserter);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong GetInserterPosition(IntPtr inserter);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong GetInserterLength(IntPtr inserter);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertBoolean(IntPtr inserter, bool value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertByte(IntPtr inserter, byte value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertSByte(IntPtr inserter, sbyte value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertShort(IntPtr inserter, short value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertUShort(IntPtr inserter, ushort value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertInt(IntPtr inserter, int value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertUInt(IntPtr inserter, uint value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertLong(IntPtr inserter, long value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertULong(IntPtr inserter, ulong value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertFloat(IntPtr inserter, float value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertDouble(IntPtr inserter, double value, ulong position);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertBytes(IntPtr inserter, byte[] bytes, long length, ulong position);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void InsertString(IntPtr inserter, string value, ulong position);
        #endregion
    }
}
