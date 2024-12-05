using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public class BinaryIO
    {
        public string BinaryFilePath { get; }
        private IntPtr Reader { get; set; } = IntPtr.Zero;
        private IntPtr Writer { get; set; } = IntPtr.Zero;
        private IntPtr Appender { get; set; } = IntPtr.Zero;
        private IntPtr Inserter { get; set; } = IntPtr.Zero;

        public ulong ReaderPosition
        {
            get
            {
                if (this.Reader == IntPtr.Zero)
                    this.Reader = BinaryIOInterop.CreateBinaryReader(this.BinaryFilePath);
                return BinaryIOInterop.GetReaderPosition(this.Reader);
            }
        }

        public ulong ReaderLength
        {
            get
            {
                if (this.Reader == IntPtr.Zero)
                    this.Reader = BinaryIOInterop.CreateBinaryReader(this.BinaryFilePath);
                return BinaryIOInterop.GetReaderLength(this.Reader);
            }
        }

        public ulong WriterPosition
        {
            get
            {
                if (this.Writer == IntPtr.Zero)
                    this.Writer = BinaryIOInterop.CreateBinaryWriter(this.BinaryFilePath);
                return BinaryIOInterop.GetWriterPosition(this.Writer);
            }
        }

        public ulong WriterLength
        {
            get
            {
                if (this.Writer == IntPtr.Zero)
                    this.Writer = BinaryIOInterop.CreateBinaryWriter(this.BinaryFilePath);
                return BinaryIOInterop.GetWriterLength(this.Writer);
            }
        }

        public ulong AppenderPosition
        {
            get
            {
                if (this.Appender == IntPtr.Zero)
                    this.Appender = BinaryIOInterop.CreateBinaryAppender(this.BinaryFilePath);
                return BinaryIOInterop.GetAppenderPosition(this.Appender);
            }
        }

        public ulong AppenderLength
        {
            get
            {
                if (this.Appender == IntPtr.Zero)
                    this.Appender = BinaryIOInterop.CreateBinaryAppender(this.BinaryFilePath);
                return BinaryIOInterop.GetAppenderLength(this.Appender);
            }
        }

        public ulong InserterPosition
        {
            get
            {
                if (this.Inserter == IntPtr.Zero)
                    this.Inserter = BinaryIOInterop.CreateBinaryInserter(this.BinaryFilePath);
                return BinaryIOInterop.GetInserterPosition(this.Inserter);
            }
        }

        public ulong InserterLength
        {
            get
            {
                if (this.Inserter == IntPtr.Zero)
                    this.Inserter = BinaryIOInterop.CreateBinaryInserter(this.BinaryFilePath);
                return BinaryIOInterop.GetInserterLength(this.Inserter);
            }
        }

        public BinaryIO(string binaryFilePath)
            => this.BinaryFilePath = binaryFilePath;

        public BINARYIO_INDICES[] GetAllIndices()
        {
            if (this.Reader == IntPtr.Zero)
                this.Reader = BinaryIOInterop.CreateBinaryReader(this.BinaryFilePath);

            IntPtr indicesPtr = BinaryIOInterop.GetAllIndices(this.Reader, out ulong count);

            if (indicesPtr == IntPtr.Zero || count == 0)
                return new BINARYIO_INDICES[0];

            BINARYIO_INDICES[] indices = new BINARYIO_INDICES[count];
            IntPtr current = indicesPtr;

            for (ulong i = 0; i < count; i++)
            {
                indices[i] = (BINARYIO_INDICES) Marshal.PtrToStructure(current, typeof(BINARYIO_INDICES));
                current = IntPtr.Add(current, Marshal.SizeOf(typeof(BINARYIO_INDICES)));
            }
            BinaryIOInterop.FreeIndexArray(indicesPtr);
            return indices;
        }

        public void RemoveIndex(BINARYIO_INDICES index)
        {
            if (this.Reader == IntPtr.Zero)
                this.Reader = BinaryIOInterop.CreateBinaryReader(this.BinaryFilePath);

            BinaryIOInterop.RemoveIndex(this.Reader, this.BinaryFilePath, index);
        }

        public T Read<T>()
        {
            if (this.Reader == IntPtr.Zero)
                this.Reader = BinaryIOInterop.CreateBinaryReader(this.BinaryFilePath);

            switch (this.Reader)
            {
                case var _ when typeof(T) == typeof(bool):
                    return (T)(object)BinaryIOInterop.ReadBoolean(this.Reader);
                case var _ when typeof(T) == typeof(byte):
                    return (T)(object)BinaryIOInterop.ReadByte(this.Reader);
                case var _ when typeof(T) == typeof(sbyte):
                    return (T)(object)BinaryIOInterop.ReadSByte(this.Reader);
                case var _ when typeof(T) == typeof(short):
                    return (T)(object)BinaryIOInterop.ReadShort(this.Reader);
                case var _ when typeof(T) == typeof(ushort):
                    return (T)(object)BinaryIOInterop.ReadUShort(this.Reader);
                case var _ when typeof(T) == typeof(int):
                    return (T)(object)BinaryIOInterop.ReadInt(this.Reader);
                case var _ when typeof(T) == typeof(uint):
                    return (T)(object)BinaryIOInterop.ReadUInt(this.Reader);
                case var _ when typeof(T) == typeof(long):
                    return (T)(object)BinaryIOInterop.ReadLong(this.Reader);
                case var _ when typeof(T) == typeof(ulong):
                    return (T)(object)BinaryIOInterop.ReadULong(this.Reader);
                case var _ when typeof(T) == typeof(float):
                    return (T)(object)BinaryIOInterop.ReadFloat(this.Reader);
                case var _ when typeof(T) == typeof(double):
                    return (T)(object)BinaryIOInterop.ReadDouble(this.Reader);
                case var _ when typeof(T) == typeof(byte[]):
                    ulong bytesLength = BinaryIOInterop.NextLength(this.Reader);
                    byte[] bytesBuffer = new byte[bytesLength];
                    BinaryIOInterop.ReadBytes(this.Reader, bytesBuffer, bytesLength);
                    return (T)(object)bytesBuffer;
                case var _ when typeof(T) == typeof(string):
                    ulong stringLength = BinaryIOInterop.NextLength(this.Reader);
                    StringBuilder stringBuffer = new StringBuilder((int)stringLength);
                    BinaryIOInterop.ReadString(this.Reader, stringBuffer, stringLength);
                    return (T)(object)stringBuffer.ToString();
                default:
                    throw new TypeAccessException($"Invalid type {typeof(T).Name}");
            }
        }

        public object Read()
        {
            if (this.Reader == IntPtr.Zero)
                this.Reader = BinaryIOInterop.CreateBinaryReader(this.BinaryFilePath);

            BINARYIO_TYPE type = BinaryIOInterop.ReadType(this.Reader);

            switch (type)
            {
                case BINARYIO_TYPE.TYPE_NULL:
                    return null;
                case BINARYIO_TYPE.TYPE_BOOLEAN:
                    return BinaryIOInterop.ReadBoolean(this.Reader);
                case BINARYIO_TYPE.TYPE_BYTE:
                    return BinaryIOInterop.ReadByte(this.Reader);
                case BINARYIO_TYPE.TYPE_SBYTE:
                    return BinaryIOInterop.ReadSByte(this.Reader);
                case BINARYIO_TYPE.TYPE_SHORT:
                    return BinaryIOInterop.ReadShort(this.Reader);
                case BINARYIO_TYPE.TYPE_USHORT:
                    return BinaryIOInterop.ReadUShort(this.Reader);
                case BINARYIO_TYPE.TYPE_INT:
                    return BinaryIOInterop.ReadInt(this.Reader);
                case BINARYIO_TYPE.TYPE_UINT:
                    return BinaryIOInterop.ReadUInt(this.Reader);
                case BINARYIO_TYPE.TYPE_LONG:
                    return BinaryIOInterop.ReadLong(this.Reader);
                case BINARYIO_TYPE.TYPE_ULONG:
                    return BinaryIOInterop.ReadULong(this.Reader);
                case BINARYIO_TYPE.TYPE_FLOAT:
                    return BinaryIOInterop.ReadFloat(this.Reader);
                case BINARYIO_TYPE.TYPE_DOUBLE:
                    return BinaryIOInterop.ReadDouble(this.Reader);
                case BINARYIO_TYPE.TYPE_BYTES:
                    ulong bytesLength = BinaryIOInterop.NextLength(this.Reader);
                    byte[] bytesBuffer = new byte[bytesLength];
                    BinaryIOInterop.ReadBytes(this.Reader, bytesBuffer, bytesLength);
                    return bytesBuffer;
                case BINARYIO_TYPE.TYPE_STRING:
                    ulong stringLength = BinaryIOInterop.NextLength(this.Reader);
                    StringBuilder stringBuffer = new StringBuilder((int)stringLength);
                    BinaryIOInterop.ReadString(this.Reader, stringBuffer, stringLength);
                    return stringBuffer.ToString();
                default:
                    throw new TypeAccessException($"Invalid type {type}");
            }
        }

        public void Write<T>(T value)
        {
            if (this.Writer == IntPtr.Zero)
                this.Writer = BinaryIOInterop.CreateBinaryWriter(this.BinaryFilePath);

            switch (this.Writer)
            {
                case var _ when value is bool @bool:
                    BinaryIOInterop.WriteBoolean(this.Writer, @bool);
                    break;
                case var _ when value is byte @byte:
                    BinaryIOInterop.WriteByte(this.Writer, @byte);
                    break;
                case var _ when value is sbyte @sbyte:
                    BinaryIOInterop.WriteSByte(this.Writer, @sbyte);
                    break;
                case var _ when value is short @short:
                    BinaryIOInterop.WriteShort(this.Writer, @short);
                    break;
                case var _ when value is ushort @ushort:
                    BinaryIOInterop.WriteUShort(this.Writer, @ushort);
                    break;
                case var _ when value is int @int:
                    BinaryIOInterop.WriteInt(this.Writer, @int);
                    break;
                case var _ when value is uint @uint:
                    BinaryIOInterop.WriteUInt(this.Writer, @uint);
                    break;
                case var _ when value is long @long:
                    BinaryIOInterop.WriteLong(this.Writer, @long);
                    break;
                case var _ when value is ulong @ulong:
                    BinaryIOInterop.WriteULong(this.Writer, @ulong);
                    break;
                case var _ when value is float @float:
                    BinaryIOInterop.WriteFloat(this.Writer, @float);
                    break;
                case var _ when value is double @double:
                    BinaryIOInterop.WriteDouble(this.Writer, @double);
                    break;
                case var _ when value is byte[] @bytes:
                    BinaryIOInterop.WriteBytes(this.Writer, @bytes, @bytes.LongLength);
                    break;
                case var _ when value is string @string:
                    BinaryIOInterop.WriteString(this.Writer, @string);
                    break;
                default:
                    throw new TypeAccessException($"Invalid type {value.GetType().Name}");
            }
        }

        public void Append<T>(T value)
        {
            if (this.Appender == IntPtr.Zero)
                this.Appender = BinaryIOInterop.CreateBinaryAppender(this.BinaryFilePath);

            switch (this.Appender)
            {
                case var _ when value is bool @bool:
                    BinaryIOInterop.AppendBoolean(this.Appender, @bool);
                    break;
                case var _ when value is byte @byte:
                    BinaryIOInterop.AppendByte(this.Appender, @byte);
                    break;
                case var _ when value is sbyte @sbyte:
                    BinaryIOInterop.AppendSByte(this.Appender, @sbyte);
                    break;
                case var _ when value is short @short:
                    BinaryIOInterop.AppendShort(this.Appender, @short);
                    break;
                case var _ when value is ushort @ushort:
                    BinaryIOInterop.AppendUShort(this.Appender, @ushort);
                    break;
                case var _ when value is int @int:
                    BinaryIOInterop.AppendInt(this.Appender, @int);
                    break;
                case var _ when value is uint @uint:
                    BinaryIOInterop.AppendUInt(this.Appender, @uint);
                    break;
                case var _ when value is long @long:
                    BinaryIOInterop.AppendLong(this.Appender, @long);
                    break;
                case var _ when value is ulong @ulong:
                    BinaryIOInterop.AppendULong(this.Appender, @ulong);
                    break;
                case var _ when value is float @float:
                    BinaryIOInterop.AppendFloat(this.Appender, @float);
                    break;
                case var _ when value is double @double:
                    BinaryIOInterop.AppendDouble(this.Appender, @double);
                    break;
                case var _ when value is byte[] @bytes:
                    BinaryIOInterop.AppendBytes(this.Appender, @bytes, @bytes.LongLength);
                    break;
                case var _ when value is string @string:
                    BinaryIOInterop.AppendString(this.Appender, @string);
                    break;
                default:
                    throw new TypeAccessException($"Invalid type {value.GetType().Name}");
            }
        }

        public void Insert<T>(T value, ulong position)
        {
            if (this.Inserter == IntPtr.Zero)
                this.Inserter = BinaryIOInterop.CreateBinaryInserter(this.BinaryFilePath);

            switch (this.Inserter)
            {
                case var _ when value is bool @bool:
                    BinaryIOInterop.InsertBoolean(this.Inserter, @bool, position);
                    break;
                case var _ when value is byte @byte:
                    BinaryIOInterop.InsertByte(this.Inserter, @byte, position);
                    break;
                case var _ when value is sbyte @sbyte:
                    BinaryIOInterop.InsertSByte(this.Inserter, @sbyte, position);
                    break;
                case var _ when value is short @short:
                    BinaryIOInterop.InsertShort(this.Inserter, @short, position);
                    break;
                case var _ when value is ushort @ushort:
                    BinaryIOInterop.InsertUShort(this.Inserter, @ushort, position);
                    break;
                case var _ when value is int @int:
                    BinaryIOInterop.InsertInt(this.Inserter, @int, position);
                    break;
                case var _ when value is uint @uint:
                    BinaryIOInterop.InsertUInt(this.Inserter, @uint, position);
                    break;
                case var _ when value is long @long:
                    BinaryIOInterop.InsertLong(this.Inserter, @long, position);
                    break;
                case var _ when value is ulong @ulong:
                    BinaryIOInterop.InsertULong(this.Inserter, @ulong, position);
                    break;
                case var _ when value is float @float:
                    BinaryIOInterop.InsertFloat(this.Inserter, @float, position);
                    break;
                case var _ when value is double @double:
                    BinaryIOInterop.InsertDouble(this.Inserter, @double, position);
                    break;
                case var _ when value is byte[] @bytes:
                    BinaryIOInterop.InsertBytes(this.Inserter, @bytes, @bytes.LongLength, position);
                    break;
                case var _ when value is string @string:
                    BinaryIOInterop.InsertString(this.Inserter, @string, position);
                    break;
                default:
                    throw new TypeAccessException($"Invalid type {value.GetType().Name}");
            }
        }

        public void Close()
        {
            if (this.Reader != IntPtr.Zero)
                BinaryIOInterop.DestroyBinaryReader(this.Reader);
            if (this.Writer != IntPtr.Zero)
                BinaryIOInterop.DestroyBinaryWriter(this.Writer);
            if (this.Appender != IntPtr.Zero)
                BinaryIOInterop.DestroyBinaryAppender(this.Appender);
            if (this.Inserter != IntPtr.Zero)
                BinaryIOInterop.DestroyBinaryInserter(this.Inserter);
        }
    }
}
