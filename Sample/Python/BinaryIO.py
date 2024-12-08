from ctypes import WinDLL, create_string_buffer
import enum

DllPath = "Sample\\Dll\\Ais.IO.dll"
DLL = WinDLL(DllPath)

class BINARYIO_TYPE(enum.Enum):
    TYPE_NULL = 0
    TYPE_BOOLEAN = 1
    TYPE_BYTE = 2
    TYPE_SBYTE = 3
    TYPE_SHORT = 4
    TYPE_USHORT = 5
    TYPE_INT = 6
    TYPE_UINT = 7
    TYPE_LONG = 8
    TYPE_ULONG = 9
    TYPE_FLOAT = 10
    TYPE_DOUBLE = 11
    TYPE_BYTES = 12
    TYPE_STRING = 13

class Binary:
    '''
    通用的二進位類別
    '''

    def CreateBuffer(length):
        '''
        建立緩衝區
        '''
        return create_string_buffer(length)