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

class Appender:
    '''
    使用二進位加入
    '''

    def CreateBinaryAppender(path):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - CreateBinaryAppender

        參數:
            - path = 路徑
        '''
        DLL.CreateBinaryAppender.argtypes = [c_char_p]
        DLL.CreateBinaryAppender.restype = c_void_p
        return DLL.CreateBinaryAppender(path)

    def DestroyBinaryAppender(appender):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - DestroyBinaryAppender

        參數:
            - appender = 加入器
        '''
        DLL.DestroyBinaryAppender.argtypes = [c_void_p]
        DLL.DestroyBinaryAppender.restype = None
        DLL.DestroyBinaryAppender(appender)

    def GetAppenderPosition(appender):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - GetAppenderPosition

        參數:
            - appender = 加入器
        '''
        DLL.GetAppenderPosition.argtypes = [c_void_p]
        DLL.GetAppenderPosition.restype = c_ulonglong
        return DLL.GetAppenderPosition(appender)

    def GetAppenderLength(appender):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - GetAppenderLength

        參數:
            - appender = 加入器
        '''
        DLL.GetAppenderLength.argtypes = [c_void_p]
        DLL.GetAppenderLength.restype = c_ulonglong
        return DLL.GetAppenderLength(appender)

    def AppendBoolean(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendBoolean

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendBoolean.argtypes = [c_void_p, c_bool]
        DLL.AppendBoolean.restype = None
        DLL.AppendBoolean(appender, value)

    def AppendByte(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendByte

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendByte.argtypes = [c_void_p, c_ubyte]
        DLL.AppendByte.restype = None
        DLL.AppendByte(appender, value)

    def AppendSByte(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendSByte

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendSByte.argtypes = [c_void_p, c_byte]
        DLL.AppendSByte.restype = None
        DLL.AppendSByte(appender, value)

    def AppendShort(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendShort

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendShort.argtypes = [c_void_p, c_short]
        DLL.AppendShort.restype = None
        DLL.AppendShort(appender, value)

    def AppendUShort(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendUShort

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendUShort.argtypes = [c_void_p, c_ushort]
        DLL.AppendUShort.restype = None
        DLL.AppendUShort(appender, value)

    def AppendInt(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendInt

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendInt.argtypes = [c_void_p, c_int]
        DLL.AppendInt.restype = None
        DLL.AppendInt(appender, value)

    def AppendUInt(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendUInt

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendUInt.argtypes = [c_void_p, c_uint]
        DLL.AppendUInt.restype = None
        DLL.AppendUInt(appender, value)

    def AppendLong(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendLong

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendLong.argtypes = [c_void_p, c_longlong]
        DLL.AppendLong.restype = None
        DLL.AppendLong(appender, value)

    def AppendULong(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendULong

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendULong.argtypes = [c_void_p, c_ulonglong]
        DLL.AppendULong.restype = None
        DLL.AppendULong(appender, value)

    def AppendFloat(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendFloat

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendFloat.argtypes = [c_void_p, c_float]
        DLL.AppendFloat.restype = None
        DLL.AppendFloat(appender, value)

    def AppendDouble(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendDouble

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendDouble.argtypes = [c_void_p, c_double]
        DLL.AppendDouble.restype = None
        DLL.AppendDouble(appender, value)

    def AppendBytes(appender, value, length):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendBytes

        參數:
            - appender = 加入器
            - value = 值
            - length = 長度
        '''
        DLL.AppendBytes.argtypes = [c_void_p, c_char_p, c_ulonglong]
        DLL.AppendBytes.restype = None
        DLL.AppendBytes(appender, value, length)

    def AppendString(appender, value):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - AppendString

        參數:
            - appender = 加入器
            - value = 值
        '''
        DLL.AppendString.argtypes = [c_void_p, c_char_p]
        DLL.AppendString.restype = None
        DLL.AppendString(appender, value)
