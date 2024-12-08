from BinaryReaderIO import Reader
from BinaryWriterIO import Writer
from BinaryAppenderIO import Appender
from BinaryInserterIO import Inserter
from BinaryIO import Binary, BINARYIO_TYPE

def StartWrite(filePath):
    '''
    寫入器的功能測試
    '''
    writer = Writer.CreateBinaryWriter(filePath)

    Writer.WriteBoolean(writer, True)
    Writer.WriteByte(writer, 0xFF)
    Writer.WriteSByte(writer, 0x7F)
    Writer.WriteShort(writer, 0x7FFF)
    Writer.WriteUShort(writer, 0xFFFF)
    Writer.WriteInt(writer, 0x7FFFFFFF)
    Writer.WriteUInt(writer, 0XFFFFFFFF)
    Writer.WriteLong(writer, 0x7FFFFFFFFFFFFFFF)
    Writer.WriteULong(writer, 0xFFFFFFFFFFFFFFFF)
    Writer.WriteFloat(writer, 3.1415927)
    Writer.WriteDouble(writer, 3.141592653589793)
    bbytes = b"This is Ais.IO Release Function Byte Array."
    Writer.WriteBytes(writer, bbytes, len(bbytes))
    
    bstring = b"This is Ais.IO Release Function String."
    Writer.WriteString(writer, bstring)

    Writer.DestroyBinaryWriter(writer)

def StartAppend(filePath):
    '''
    加入器的功能測試
    '''
    appender = Appender.CreateBinaryAppender(filePath)

    Appender.AppendBoolean(appender, True)
    Appender.AppendByte(appender, 0xFF)
    Appender.AppendSByte(appender, 0x7F)
    Appender.AppendShort(appender, 0x7FFF)
    Appender.AppendUShort(appender, 0xFFFF)
    Appender.AppendInt(appender, 0x7FFFFFFF)
    Appender.AppendUInt(appender, 0XFFFFFFFF)
    Appender.AppendLong(appender, 0x7FFFFFFFFFFFFFFF)
    Appender.AppendULong(appender, 0xFFFFFFFFFFFFFFFF)
    Appender.AppendFloat(appender, 3.1415927)
    Appender.AppendDouble(appender, 3.141592653589793)
    bbytes = b"This is Ais.IO Release Function Byte Array."
    Appender.AppendBytes(appender, bbytes, len(bbytes))
    
    bstring = b"This is Ais.IO Release Function String."
    Appender.AppendString(appender, bstring)

    Appender.DestroyBinaryAppender(appender)

def StartInsert(filePath):
    '''
    插入器的功能測試
    '''
    inserter = Inserter.CreateBinaryInserter(filePath)

    Inserter.InsertBoolean(inserter, True, 0)
    Inserter.InsertByte(inserter, 0xFF, 0)
    Inserter.InsertSByte(inserter, 0x7F, 0)
    Inserter.InsertShort(inserter, 0x7FFF, 0)
    Inserter.InsertUShort(inserter, 0xFFFF, 0)
    Inserter.InsertInt(inserter, 0x7FFFFFFF, 0)
    Inserter.InsertUInt(inserter, 0XFFFFFFFF, 0)
    Inserter.InsertLong(inserter, 0x7FFFFFFFFFFFFFFF, 0)
    Inserter.InsertULong(inserter, 0xFFFFFFFFFFFFFFFF, 0)
    Inserter.InsertFloat(inserter, 3.1415927, 0)
    Inserter.InsertDouble(inserter, 3.141592653589793, 0)
    bbytes = b"This is Ais.IO Release Function Byte Array."
    Inserter.InsertBytes(inserter, bbytes, len(bbytes), 0)
    
    bstring = b"This is Ais.IO Release Function String."
    Inserter.InsertString(inserter, bstring, 0)

    Inserter.DestroyBinaryInserter(inserter)

def StartRead(filePath):
    '''
    讀取器的功能測試
    '''
    reader = Reader.CreateBinaryReader(filePath)

    rbool = Reader.ReadBoolean(reader)
    rbyte = Reader.ReadByte(reader)
    rsbyte = Reader.ReadSByte(reader)
    rshort = Reader.ReadShort(reader)
    rushort = Reader.ReadUShort(reader)
    rint = Reader.ReadInt(reader)
    ruint = Reader.ReadUInt(reader)
    rlong = Reader.ReadLong(reader)
    rulong = Reader.ReadULong(reader)
    rfloat = Reader.ReadFloat(reader)
    rdouble = Reader.ReadDouble(reader)

    nextLength = Reader.NextLength(reader)
    bytesBuffer = Binary.CreateBuffer(nextLength)
    Reader.ReadBytes(reader, bytesBuffer, nextLength)
    rbytes = bytesBuffer.value

    nextLength = Reader.NextLength(reader)
    stringBuffer = Binary.CreateBuffer(nextLength)
    Reader.ReadString(reader, stringBuffer, nextLength)
    rstring = stringBuffer.value

    Reader.DestroyBinaryReader(reader)

    message = [
        f"bool = {rbool}",
        f"byte = {rbyte}",
        f"sbyte = {rsbyte}",
        f"short = {rshort}",
        f"ushort = {rushort}",
        f"int = {rint}",
        f"uint = {ruint}",
        f"long = {rlong}",
        f"ulong = {rulong}",
        f"float = {rfloat}",
        f"double = {rdouble}",
        f"bytes = {rbytes}",
        f"string = {rstring}",
    ]
    print(str.join("\n", message))

def StartReadAll(filePath):
    '''
    讀取器的功能測試 (自動)
    '''
    reader = Reader.CreateBinaryReader(filePath)
    message = ""
    count = 0
    while (Reader.GetReaderPosition(reader) < Reader.GetReaderLength(reader)):
        type = Reader.ReadType(reader)
        match (type):
            case BINARYIO_TYPE.TYPE_BOOLEAN:
                message += f"{count}. Boolean : {Reader.ReadBoolean(reader)}\n"
            case BINARYIO_TYPE.TYPE_BYTE:
                message += f"{count}. Byte : {Reader.ReadByte(reader)}\n"
            case BINARYIO_TYPE.TYPE_SBYTE:
                message += f"{count}. SByte : {Reader.ReadSByte(reader)}\n"
            case BINARYIO_TYPE.TYPE_SHORT:
                message += f"{count}. Short : {Reader.ReadShort(reader)}\n"
            case BINARYIO_TYPE.TYPE_USHORT:
                message += f"{count}. UShort : {Reader.ReadUShort(reader)}\n"
            case BINARYIO_TYPE.TYPE_INT:
                message += f"{count}. Int : {Reader.ReadInt(reader)}\n"
            case BINARYIO_TYPE.TYPE_UINT:
                message += f"{count}. UInt : {Reader.ReadUInt(reader)}\n"
            case BINARYIO_TYPE.TYPE_LONG:
                message += f"{count}. Long : {Reader.ReadLong(reader)}\n"
            case BINARYIO_TYPE.TYPE_ULONG:
                message += f"{count}. ULong : {Reader.ReadULong(reader)}\n"
            case BINARYIO_TYPE.TYPE_FLOAT:
                message += f"{count}. Float : {Reader.ReadFloat(reader)}\n"
            case BINARYIO_TYPE.TYPE_DOUBLE:
                message += f"{count}. Double : {Reader.ReadDouble(reader)}\n"
            case BINARYIO_TYPE.TYPE_BYTES:
                nextLength = Reader.NextLength(reader)
                bytesBuffer = Binary.CreateBuffer(nextLength)
                Reader.ReadBytes(reader, bytesBuffer, nextLength)
                message += f"{count}. Bytes : {bytesBuffer.value.decode()}\n"
            case BINARYIO_TYPE.TYPE_STRING:
                nextLength = Reader.NextLength(reader)
                stringBuffer = Binary.CreateBuffer(nextLength)
                Reader.ReadString(reader, stringBuffer, nextLength)
                message += f"{count}. String : {stringBuffer.value.decode()}\n"
            case _:
                message += "N{count}. ull : None\n"

        count += 1
                
    print(message)

if __name__ == "__main__":
    filePath = b"Sample\\File\\test.bin"

    # Binary Writer
    StartWrite(filePath)

    # Binary Appender
    for i in range(1000):
        StartAppend(filePath)

    # Binary Inserter
    StartInsert(filePath)

    # Binary Reader (All)
    StartReadAll(filePath)

    # # Binary Reader
    # StartRead(filePath)