# 原始字串
string = "This is 測試，來自 Ais.IO DLL、SO 模組，而這次我打多點字，來確定加密成功 (By Base10 - Encode && Decode)"

# 將字串轉為 bytes，使用 UTF-8 編碼
byte_data = string.encode('utf-8')

# 將 bytes 轉為大整數，big endian 是常用格式
big_int = int.from_bytes(byte_data, byteorder='big')
print("Big Integer:", big_int)

restored_bytes = big_int.to_bytes(len(byte_data), byteorder='big')
# 還原字串
restored_string = restored_bytes.decode('utf-8')
print("Restored string:", restored_string)