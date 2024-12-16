using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    // DES_CBC_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct DES_CBC_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public bool PKCS7_PADDING;                  // 是否填充 PKCS#7
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
    }

    // DES_CBC_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct DES_CBC_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public bool PKCS7_PADDING;                  // 是否填充 PKCS#7
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
    }

    // DES_CFB_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct DES_CFB_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public SEGMENT_SIZE_OPTION SEGMENT_SIZE;    // 分段大小
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
    };

    // DES_CFB_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct DES_CFB_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public SEGMENT_SIZE_OPTION SEGMENT_SIZE;    // 分段大小
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
    };

    // DES_OFB_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct DES_OFB_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
    };

    // DES_OFB_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct DES_OFB_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
    };

    // DES_ECB_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct DES_ECB_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public bool PKCS7_PADDING;                  // 是否填充 PKCS#7
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
    }

    // DES_ECB_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct DES_ECB_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public bool PKCS7_PADDING;                  // 是否填充 PKCS#7
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
    }

    // DES_WRAP_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct DES_WRAP_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr KEK;                          // 指向包裝密鑰
        public IntPtr WRAP_KEY;                     // 指向已包裝密鑰輸出
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr KEK_LENGTH;                  // 包裝密鑰長度 (16、24 或 32 位元組)
        public UIntPtr WRAP_KEY_LENGTH;             // 已包裝密鑰輸出長度
    };

    // DES_WRAP_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct DES_WRAP_DECRYPT
    {
        public IntPtr WRAP_KEY;                     // 指向已包裝密鑰
        public IntPtr KEK;                          // 指向包裝密鑰
        public IntPtr KEY;                          // 指向解包密鑰的緩衝區
        public UIntPtr WRAP_KEY_LENGTH;             // 已包裝密鑰長度
        public UIntPtr KEK_LENGTH;                  // 包裝金鑰長度 (16、24 或 32 位元組)
        public UIntPtr KEY_LENGTH;                  // 解包密鑰的輸出長度
    };
}
