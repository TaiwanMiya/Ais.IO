using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    // AES_CTR_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CTR_ENCRYPT
    {
        public IntPtr PLAIN_TEXT;           // 指向明文數據
        public IntPtr KEY;                  // 指向密鑰
        public IntPtr IV;                   // 指向 IV
        public UIntPtr PLAIN_TEXT_LENGTH;   // 明文長度
        public IntPtr CIPHER_TEXT;          // 指向密文輸出數據
        public long COUNTER;                // 計數器
    }

    // AES_CTR_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CTR_DECRYPT
    {
        public IntPtr CIPHER_TEXT;          // 指向密文數據
        public IntPtr KEY;                  // 指向密鑰
        public IntPtr IV;                   // 指向 IV
        public UIntPtr CIPHER_TEXT_LENGTH;  // 密文長度
        public IntPtr PLAIN_TEXT;           // 指向明文輸出數據
        public long COUNTER;                // 計數器
    }

    // AES_CBC_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CBC_ENCRYPT
    {
        public IntPtr PLAIN_TEXT;           // 指向明文數據
        public IntPtr KEY;                  // 指向密鑰
        public IntPtr IV;                   // 指向 IV
        public UIntPtr PLAIN_TEXT_LENGTH;   // 明文長度
        public IntPtr CIPHER_TEXT;          // 指向密文輸出數據
        public bool PKCS7_PADDING;          // 是否填充 PKCS#7
    }

    // AES_CBC_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CBC_DECRYPT
    {
        public IntPtr CIPHER_TEXT;          // 指向密文數據
        public IntPtr KEY;                  // 指向密鑰
        public IntPtr IV;                   // 指向 IV
        public UIntPtr CIPHER_TEXT_LENGTH;  // 密文長度
        public IntPtr PLAIN_TEXT;           // 指向明文輸出數據
        public bool PKCS7_PADDING;          // 是否填充 PKCS#7
    }
}
