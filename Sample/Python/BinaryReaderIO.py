from BinaryIO import DLL, BINARYIO_TYPE
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
                    c_double)

class Reader:
    '''
    使用二進位讀取
    '''

    def ReadType(reader) -> BINARYIO_TYPE:
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadType

        參數:
            - reader = 讀取器
        '''
        DLL.ReadType.argtypes = [c_void_p]
        DLL.ReadType.restype = BINARYIO_TYPE
        return DLL.ReadType(reader)

    def NextLength(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - NextLength

        參數:
            - reader = 讀取器
        '''
        DLL.NextLength.argtypes = [c_void_p]
        DLL.NextLength.restype = c_ulonglong
        return DLL.NextLength(reader)
        
    def CreateBinaryReader(path):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - CreateBinaryReader

        參數:
            - path = 路徑
        '''
        DLL.CreateBinaryReader.argtypes = [c_char_p]
        DLL.CreateBinaryReader.restype = c_void_p
        return DLL.CreateBinaryReader(path)
        
    def DestroyBinaryReader(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - DestroyBinaryReader

        參數:
            - reader = 讀取器
        '''
        DLL.DestroyBinaryReader.argtypes = [c_void_p]
        DLL.DestroyBinaryReader.restype = None
        DLL.DestroyBinaryReader(reader)
        
    def GetReaderPosition(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - GetReaderPosition

        參數:
            - reader = 讀取器
        '''
        DLL.GetReaderPosition.argtypes = [c_void_p]
        DLL.GetReaderPosition.restype = c_ulonglong
        return DLL.GetReaderPosition(reader)
        
    def GetReaderLength(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - GetReaderLength

        參數:
            - reader = 讀取器
        '''
        DLL.GetReaderLength.argtypes = [c_void_p]
        DLL.GetReaderLength.restype = c_ulonglong
        return DLL.GetReaderLength(reader)
        
    def ReadBoolean(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadBoolean

        參數:
            - reader = 讀取器
        '''
        DLL.ReadBoolean.argtypes = [c_void_p]
        DLL.ReadBoolean.restype = c_bool
        return DLL.ReadBoolean(reader)
        
    def ReadByte(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadByte

        參數:
            - reader = 讀取器
        '''
        DLL.ReadByte.argtypes = [c_void_p]
        DLL.ReadByte.restype = c_ubyte
        return DLL.ReadByte(reader)
        
    def ReadSByte(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadSByte

        參數:
            - reader = 讀取器
        '''
        DLL.ReadSByte.argtypes = [c_void_p]
        DLL.ReadSByte.restype = c_byte
        return DLL.ReadSByte(reader)
        
    def ReadShort(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadShort

        參數:
            - reader = 讀取器
        '''
        DLL.ReadShort.argtypes = [c_void_p]
        DLL.ReadShort.restype = c_short
        return DLL.ReadShort(reader)
        
    def ReadUShort(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadUShort

        參數:
            - reader = 讀取器
        '''
        DLL.ReadUShort.argtypes = [c_void_p]
        DLL.ReadUShort.restype = c_ushort
        return DLL.ReadUShort(reader)
        
    def ReadInt(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadInt

        參數:
            - reader = 讀取器
        '''
        DLL.ReadInt.argtypes = [c_void_p]
        DLL.ReadInt.restype = c_int
        return DLL.ReadInt(reader)
        
    def ReadUInt(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadUInt

        參數:
            - reader = 讀取器
        '''
        DLL.ReadUInt.argtypes = [c_void_p]
        DLL.ReadUInt.restype = c_uint
        return DLL.ReadUInt(reader)
        
    def ReadLong(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadLong

        參數:
            - reader = 讀取器
        '''
        DLL.ReadLong.argtypes = [c_void_p]
        DLL.ReadLong.restype = c_longlong
        return DLL.ReadLong(reader)
        
    def ReadULong(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadULong

        參數:
            - reader = 讀取器
        '''
        DLL.ReadULong.argtypes = [c_void_p]
        DLL.ReadULong.restype = c_ulonglong
        return DLL.ReadULong(reader)
        
    def ReadFloat(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadFloat

        參數:
            - reader = 讀取器
        '''
        DLL.ReadFloat.argtypes = [c_void_p]
        DLL.ReadFloat.restype = c_float
        return DLL.ReadFloat(reader)
        
    def ReadDouble(reader):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadDouble

        參數:
            - reader = 讀取器
        '''
        DLL.ReadDouble.argtypes = [c_void_p]
        DLL.ReadDouble.restype = c_double
        return DLL.ReadDouble(reader)
        
    def ReadBytes(reader, buffer, length):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadBytes

        參數:
            - - reader = 讀取器
            - buffer = 緩衝區
            - length = 緩衝長度
        '''
        DLL.ReadBytes.argtypes = [c_void_p, c_char_p, c_ulonglong]
        DLL.ReadBytes.restype = None
        return DLL.ReadBytes(reader, buffer, length)
        
    def ReadString(reader, buffer, length):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - ReadString

        參數:
            - - reader = 讀取器
            - buffer = 緩衝區
            - length = 緩衝長度
        '''
        DLL.ReadString.argtypes = [c_void_p, c_char_p, c_int]
        DLL.ReadString.restype = None
        return DLL.ReadString(reader, buffer, length)
