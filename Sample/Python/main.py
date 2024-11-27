import ctypes
from ctypes import (c_void_p,
                    c_char_p,
                    c_bool,
                    c_ubyte,
                    c_byte,
                    c_short,
                    c_ushort,
                    c_int,
                    c_uint,
                    c_longlong,
                    c_ulonglong,
                    c_float,
                    c_double,
                    c_size_t)

DllPath = "./DLL/Ais.IO.Source.dll"
DLL = ctypes.WinDLL(DllPath)

# NextLength
DLL.NextLength.argtypes = [c_void_p]
DLL.NextLength.restype = c_ulonglong

# CreateBinaryReader
DLL.CreateBinaryReader.argtypes = [c_char_p]
DLL.CreateBinaryReader.restype = c_void_p

# DestroyBinaryReader
DLL.DestroyBinaryReader.argtypes = [c_void_p]
DLL.DestroyBinaryReader.restype = None

# GetReaderPosition
DLL.GetReaderPosition.argtypes = [c_void_p]
DLL.GetReaderPosition.restype = c_ulonglong

# GetReaderLength
DLL.GetReaderLength.argtypes = [c_void_p]
DLL.GetReaderLength.restype = c_ulonglong

# ReadBoolean
DLL.ReadBoolean.argtypes = [c_void_p]
DLL.ReadBoolean.restype = c_bool

# ReadByte
DLL.ReadByte.argtypes = [c_void_p]
DLL.ReadByte.restype = c_ubyte

# ReadSByte
DLL.ReadSByte.argtypes = [c_void_p]
DLL.ReadSByte.restype = c_byte

# ReadShort
DLL.ReadShort.argtypes = [c_void_p]
DLL.ReadShort.restype = c_short

# ReadUShort
DLL.ReadUShort.argtypes = [c_void_p]
DLL.ReadUShort.restype = c_ushort

# ReadInt
DLL.ReadInt.argtypes = [c_void_p]
DLL.ReadInt.restype = c_int

# ReadUInt
DLL.ReadUInt.argtypes = [c_void_p]
DLL.ReadUInt.restype = c_uint

# ReadLong
DLL.ReadLong.argtypes = [c_void_p]
DLL.ReadLong.restype = c_longlong

# ReadULong
DLL.ReadULong.argtypes = [c_void_p]
DLL.ReadULong.restype = c_ulonglong

# ReadFloat
DLL.ReadFloat.argtypes = [c_void_p]
DLL.ReadFloat.restype = c_float

# ReadDouble
DLL.ReadDouble.argtypes = [c_void_p]
DLL.ReadDouble.restype = c_double

# ReadBytes
DLL.ReadBytes.argtypes = [c_void_p, c_char_p, c_ulonglong]
DLL.ReadBytes.restype = None

# ReadString
DLL.ReadString.argtypes = [c_void_p, c_char_p, c_int]
DLL.ReadString.restype = None

# CreateBinaryWriter
DLL.CreateBinaryWriter.argtypes = [c_char_p]
DLL.CreateBinaryWriter.restype = c_void_p

# DestroyBinaryWriter
DLL.DestroyBinaryWriter.argtypes = [c_void_p]
DLL.DestroyBinaryWriter.restype = None

# GetWriterPosition
DLL.GetWriterPosition.argtypes = [c_void_p]
DLL.GetWriterPosition.restype = c_ulonglong

# GetWriterLength
DLL.GetWriterLength.argtypes = [c_void_p]
DLL.GetWriterLength.restype = c_ulonglong

# WriteBoolean
DLL.WriteBoolean.argtypes = [c_void_p, c_bool]
DLL.WriteBoolean.restype = None

# WriteByte
DLL.WriteByte.argtypes = [c_void_p, c_ubyte]
DLL.WriteByte.restype = None

# WriteSByte
DLL.WriteSByte.argtypes = [c_void_p, c_byte]
DLL.WriteSByte.restype = None

# WriteShort
DLL.WriteShort.argtypes = [c_void_p, c_short]
DLL.WriteShort.restype = None

# WriteUShort
DLL.WriteUShort.argtypes = [c_void_p, c_ushort]
DLL.WriteUShort.restype = None

# WriteInt
DLL.WriteInt.argtypes = [c_void_p, c_int]
DLL.WriteInt.restype = None

# WriteUInt
DLL.WriteUInt.argtypes = [c_void_p, c_uint]
DLL.WriteUInt.restype = None

# WriteLong
DLL.WriteLong.argtypes = [c_void_p, c_longlong]
DLL.WriteLong.restype = None

# WriteULong
DLL.WriteULong.argtypes = [c_void_p, c_ulonglong]
DLL.WriteULong.restype = None

# WriteFloat
DLL.WriteFloat.argtypes = [c_void_p, c_float]
DLL.WriteFloat.restype = None

# WriteDouble
DLL.WriteDouble.argtypes = [c_void_p, c_double]
DLL.WriteDouble.restype = None

# WriteBytes
DLL.WriteBytes.argtypes = [c_void_p, c_char_p, c_ulonglong]
DLL.WriteBytes.restype = None

# WriteString
DLL.WriteString.argtypes = [c_void_p, c_char_p]
DLL.WriteString.restype = None

if __name__ == "__main__":
    filePath = b"./File/test.bin"
    reader = DLL.CreateBinaryReader(filePath)

    rbool = DLL.ReadBoolean(reader)
    rshort = DLL.ReadShort(reader)
    rint = DLL.ReadInt(reader)
    rlong = DLL.ReadLong(reader)
    rbyte = DLL.ReadByte(reader)
    rsbyte = DLL.ReadSByte(reader)
    rushort = DLL.ReadUShort(reader)
    ruint = DLL.ReadUInt(reader)
    rulong = DLL.ReadULong(reader)
    rfloat = DLL.ReadFloat(reader)
    rdouble = DLL.ReadDouble(reader)

    nextLength = DLL.NextLength(reader)
    stringBuffer = ctypes.create_string_buffer(nextLength)
    DLL.ReadString(reader, stringBuffer, nextLength)
    rstring = stringBuffer.value

    nextLength = DLL.NextLength(reader)
    bytesBuffer = ctypes.create_string_buffer(nextLength)
    DLL.ReadBytes(reader, bytesBuffer, nextLength)
    rbytes = bytesBuffer.value

    message = [
        f"bool = {rbool}",
        f"short = {rshort}",
        f"int = {rint}",
        f"long = {rlong}",
        f"byte = {rbyte}",
        f"sbyte = {rsbyte}",
        f"ushort = {rushort}",
        f"uint = {ruint}",
        f"ulong = {rulong}",
        f"float = {rfloat}",
        f"double = {rdouble}",
        f"string = {rstring}",
        f"bytes = {rbytes}",
    ]
    print(str.join("\n", message))