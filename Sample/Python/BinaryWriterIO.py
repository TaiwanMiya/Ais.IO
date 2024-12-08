from BinaryIO import DLL
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

class Writer:
    '''
    使用二進位寫入
    '''

    def CreateBinaryWriter(path):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - CreateBinaryWriter

        參數:
            - path = 路徑
        '''
        DLL.CreateBinaryWriter.argtypes = [c_char_p]
        DLL.CreateBinaryWriter.restype = c_void_p
        return DLL.CreateBinaryWriter(path)

    def DestroyBinaryWriter(writer):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - DestroyBinaryWriter

        參數:
            - writer = 寫入器
        '''
        DLL.DestroyBinaryWriter.argtypes = [c_void_p]
        DLL.DestroyBinaryWriter.restype = None
        DLL.DestroyBinaryWriter(writer)

    def GetWriterPosition(writer):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - GetWriterPosition

        參數:
            - writer = 寫入器
        '''
        DLL.GetWriterPosition.argtypes = [c_void_p]
        DLL.GetWriterPosition.restype = c_ulonglong
        return DLL.GetWriterPosition(writer)

    def GetWriterLength(writer):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - GetWriterLength

        參數:
            - writer = 寫入器
        '''
        DLL.GetWriterLength.argtypes = [c_void_p]
        DLL.GetWriterLength.restype = c_ulonglong
        return DLL.GetWriterLength(writer)

    def WriteBoolean(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteBoolean

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteBoolean.argtypes = [c_void_p, c_bool]
        DLL.WriteBoolean.restype = None
        DLL.WriteBoolean(writer, value)

    def WriteByte(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteByte

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteByte.argtypes = [c_void_p, c_ubyte]
        DLL.WriteByte.restype = None
        DLL.WriteByte(writer, value)

    def WriteSByte(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteSByte

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteSByte.argtypes = [c_void_p, c_byte]
        DLL.WriteSByte.restype = None
        DLL.WriteSByte(writer, value)

    def WriteShort(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteShort

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteShort.argtypes = [c_void_p, c_short]
        DLL.WriteShort.restype = None
        DLL.WriteShort(writer, value)

    def WriteUShort(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteUShort

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteUShort.argtypes = [c_void_p, c_ushort]
        DLL.WriteUShort.restype = None
        DLL.WriteUShort(writer, value)

    def WriteInt(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteInt

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteInt.argtypes = [c_void_p, c_int]
        DLL.WriteInt.restype = None
        DLL.WriteInt(writer, value)

    def WriteUInt(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteUInt

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteUInt.argtypes = [c_void_p, c_uint]
        DLL.WriteUInt.restype = None
        DLL.WriteUInt(writer, value)

    def WriteLong(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteLong

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteLong.argtypes = [c_void_p, c_longlong]
        DLL.WriteLong.restype = None
        DLL.WriteLong(writer, value)

    def WriteULong(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteULong

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteULong.argtypes = [c_void_p, c_ulonglong]
        DLL.WriteULong.restype = None
        DLL.WriteULong(writer, value)

    def WriteFloat(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteFloat

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteFloat.argtypes = [c_void_p, c_float]
        DLL.WriteFloat.restype = None
        DLL.WriteFloat(writer, value)

    def WriteDouble(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteDouble

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteDouble.argtypes = [c_void_p, c_double]
        DLL.WriteDouble.restype = None
        DLL.WriteDouble(writer, value)

    def WriteBytes(writer, value, length):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteBytes

        參數:
            - writer  = 寫入器
            - value = 值
            - length = 長度
        '''
        DLL.WriteBytes.argtypes = [c_void_p, c_char_p, c_ulonglong]
        DLL.WriteBytes.restype = None
        DLL.WriteBytes(writer, value, length)

    def WriteString(writer, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - WriteString

        參數:
            - writer = 寫入器
            - value = 值
        '''
        DLL.WriteString.argtypes = [c_void_p, c_char_p]
        DLL.WriteString.restype = None
        DLL.WriteString(writer, value)
