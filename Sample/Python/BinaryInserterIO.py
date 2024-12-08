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

class Inserter:
    '''
    使用二進位插入
    '''

    def CreateBinaryInserter(path):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - CreateBinaryInserter

        參數:
            - path = 路徑
        '''
        DLL.CreateBinaryInserter.argtypes = [c_char_p]
        DLL.CreateBinaryInserter.restype = c_void_p
        return DLL.CreateBinaryInserter(path)

    def DestroyBinaryInserter(appender):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - DestroyBinaryInserter

        參數:
             - appender = 插入器
        '''
        DLL.DestroyBinaryInserter.argtypes = [c_void_p]
        DLL.DestroyBinaryInserter.restype = None
        DLL.DestroyBinaryInserter(appender)

    def GetInserterPosition(appender):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - GetInserterPosition

        參數:
             - appender = 插入器
        '''
        DLL.GetInserterPosition.argtypes = [c_void_p]
        DLL.GetInserterPosition.restype = c_ulonglong
        return DLL.GetInserterPosition(appender)

    def GetInserterLength(appender):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - GetInserterLength

        參數:
             - appender = 插入器
        '''
        DLL.GetInserterLength.argtypes = [c_void_p]
        DLL.GetInserterLength.restype = c_ulonglong
        return DLL.GetInserterLength(appender)

    def InsertBoolean(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertBoolean

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertBoolean.argtypes = [c_void_p, c_bool, c_ulonglong]
        DLL.InsertBoolean.restype = None
        DLL.InsertBoolean(inserter, value, position)

    def InsertByte(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertByte

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertByte.argtypes = [c_void_p, c_ubyte, c_ulonglong]
        DLL.InsertByte.restype = None
        DLL.InsertByte(inserter, value, position)

    def InsertSByte(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertSByte

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertSByte.argtypes = [c_void_p, c_byte, c_ulonglong]
        DLL.InsertSByte.restype = None
        DLL.InsertSByte(inserter, value, position)

    def InsertShort(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertShort

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertShort.argtypes = [c_void_p, c_short, c_ulonglong]
        DLL.InsertShort.restype = None
        DLL.InsertShort(inserter, value, position)

    def InsertUShort(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertUShort

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertUShort.argtypes = [c_void_p, c_ushort, c_ulonglong]
        DLL.InsertUShort.restype = None
        DLL.InsertUShort(inserter, value, position)

    def InsertInt(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertInt

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertInt.argtypes = [c_void_p, c_int, c_ulonglong]
        DLL.InsertInt.restype = None
        DLL.InsertInt(inserter, value, position)

    def InsertUInt(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertUInt

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertUInt.argtypes = [c_void_p, c_uint, c_ulonglong]
        DLL.InsertUInt.restype = None
        DLL.InsertUInt(inserter, value, position)

    def InsertLong(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertLong

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertLong.argtypes = [c_void_p, c_longlong, c_ulonglong]
        DLL.InsertLong.restype = None
        DLL.InsertLong(inserter, value, position)

    def InsertULong(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertULong

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertULong.argtypes = [c_void_p, c_ulonglong, c_ulonglong]
        DLL.InsertULong.restype = None
        DLL.InsertULong(inserter, value, position)

    def InsertFloat(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertFloat

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertFloat.argtypes = [c_void_p, c_float, c_ulonglong]
        DLL.InsertFloat.restype = None
        DLL.InsertFloat(inserter, value, position)

    def InsertDouble(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertDouble

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertDouble.argtypes = [c_void_p, c_double, c_ulonglong]
        DLL.InsertDouble.restype = None
        DLL.InsertDouble(inserter, value, position)

    def InsertBytes(inserter, value, length, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertBytes

        參數:
            - inserter = 插入器
            - value = 值
            - length = 長度
            - position = 位置
        '''
        DLL.InsertBytes.argtypes = [c_void_p, c_char_p, c_ulonglong, c_ulonglong]
        DLL.InsertBytes.restype = None
        DLL.InsertBytes(inserter, value, length, position)

    def InsertString(inserter, value, position):
        '''
        C/C++ 內部的 Ais.IO.dll 方法:
            - InsertString

        參數:
            - inserter = 插入器
            - value = 值
            - position = 位置
        '''
        DLL.InsertString.argtypes = [c_void_p, c_char_p, c_ulonglong]
        DLL.InsertString.restype = None
        DLL.InsertString(inserter, value, position)
