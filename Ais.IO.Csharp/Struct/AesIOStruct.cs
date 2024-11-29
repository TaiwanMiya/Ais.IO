using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CTR_ENCRYPT
    {
        public IntPtr PLAIN_TEXT;           // 指向明文数据
        public IntPtr KEY;                  // 指向密钥
        public IntPtr IV;                   // 指向 IV
        public long COUNTER;                // 计数器
        public UIntPtr PLAIN_TEXT_LENGTH;   // 長度
        public IntPtr CIPHER_TEXT;          // 指向密文输出数据
    }

    // 定义 AES_CTR_DECRYPT 结构体
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CTR_DECRYPT
    {
        public IntPtr CIPHER_TEXT;          // 指向密文数据
        public IntPtr KEY;                  // 指向密钥
        public IntPtr IV;                   // 指向 IV
        public long COUNTER;                // 计数器
        public UIntPtr CIPHER_TEXT_LENGTH;  // 長度
        public IntPtr PLAIN_TEXT;           // 指向明文输出数据
    }
}
