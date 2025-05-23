﻿using System;
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
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public IntPtr IV;                           // 指向 IV
        public long COUNTER;                        // 計數器
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
    }

    // AES_CTR_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CTR_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public IntPtr IV;                           // 指向 IV
        public long COUNTER;                        // 計數器
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
    }

    // AES_CBC_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CBC_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public bool PKCS7_PADDING;                  // 是否填充 PKCS#7
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
    }

    // AES_CBC_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CBC_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public bool PKCS7_PADDING;                  // 是否填充 PKCS#7
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
    }

    // AES_CFB_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CFB_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public SEGMENT_SIZE_OPTION SEGMENT_SIZE;    // 分段大小
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
    };

    // AES_CFB_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CFB_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public SEGMENT_SIZE_OPTION SEGMENT_SIZE;    // 分段大小
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
    };

    // AES_OFB_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_OFB_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
    };

    // AES_OFB_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_OFB_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr IV;                           // 指向 IV
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
    };

    // AES_ECB_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_ECB_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public bool PKCS7_PADDING;                  // 是否填充 PKCS#7
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
    }

    // AES_ECB_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_ECB_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public bool PKCS7_PADDING;                  // 是否填充 PKCS#7
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
    }

    // AES_GCM_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_GCM_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr NONCE;                        // 指向唯一值
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public IntPtr TAG;                          // 指向認證標籤
        public IntPtr AAD;                          // 指向附加驗證資料
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
        public UIntPtr NONCE_LENGTH;                // 指向唯一值長度
        public UIntPtr TAG_LENGTH;                  // 認證標籤長度
        public UIntPtr AAD_LENGTH;                  // 附加驗證資料長度
    };

    // AES_GCM_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_GCM_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr NONCE;                        // 指向唯一值
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public IntPtr TAG;                          // 指向認證標籤
        public IntPtr AAD;                          // 指向附加驗證資料
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
        public UIntPtr NONCE_LENGTH;                // 唯一值長度
        public UIntPtr TAG_LENGTH;                  // 認證標籤長度
        public UIntPtr AAD_LENGTH;                  // 附加驗證資料長度
    };

    // AES_CCM_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CCM_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr NONCE;                        // 指向唯一值
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public IntPtr TAG;                          // 指向認證標籤
        public IntPtr AAD;                          // 指向附加驗證資料
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
        public UIntPtr NONCE_LENGTH;                // 唯一值長度
        public UIntPtr TAG_LENGTH;                  // 認證標籤長度
        public UIntPtr AAD_LENGTH;                  // 附加驗證資料長度
    };

    // AES_CCM_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_CCM_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr NONCE;                        // 指向唯一值
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public IntPtr TAG;                          // 指向認證標籤
        public IntPtr AAD;                          // 指向附加驗證資料
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
        public UIntPtr NONCE_LENGTH;                // 唯一值長度
        public UIntPtr TAG_LENGTH;                  // 認證標籤長度
        public UIntPtr AAD_LENGTH;                  // 附加驗證資料長度
    };

    // AES_XTS_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_XTS_ENCRYPT
    {
        public IntPtr KEY1;                         // 指向數據加密密鑰
        public IntPtr PLAIN_TEXT;                   // 指向明文數據
        public IntPtr CIPHER_TEXT;                  // 指向密文輸出數據
        public IntPtr KEY2;                         // 指向扭曲值密鑰
        public IntPtr TWEAK;                        // 扭曲值，通常是磁碟扇區編號
        public UIntPtr KEY1_LENGTH;                 // 數據加密密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 明文長度
        public UIntPtr KEY2_LENGTH;                 // 扭曲值密鑰長度
    };

    // AES_XTS_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_XTS_DECRYPT
    {
        public IntPtr KEY1;                         // 指向數據加密密鑰
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public IntPtr KEY2;                         // 指向扭曲值密鑰
        public IntPtr TWEAK;                        // 扭曲值，通常是磁碟扇區編號
        public UIntPtr KEY1_LENGTH;                 // 數據加密密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
        public UIntPtr KEY2_LENGTH;                 // 扭曲值密鑰長度
    };

    // AES_OCB_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_OCB_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr NONCE;                        // 指向唯一值
        public IntPtr PLAIN_TEXT;                   // 指向密文數據
        public IntPtr CIPHER_TEXT;                  // 指向明文輸出數據
        public IntPtr TAG;                          // 指向認證標籤
        public IntPtr AAD;                          // 指向附加驗證資料
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr PLAIN_TEXT_LENGTH;           // 密文長度
        public UIntPtr NONCE_LENGTH;                // 唯一值長度
        public UIntPtr TAG_LENGTH;                  // 認證標籤長度
        public UIntPtr AAD_LENGTH;                  // 附加驗證資料長度
    };

    // AES_OCB_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_OCB_DECRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr NONCE;                        // 指向唯一值
        public IntPtr CIPHER_TEXT;                  // 指向密文數據
        public IntPtr PLAIN_TEXT;                   // 指向明文輸出數據
        public IntPtr TAG;                          // 指向認證標籤
        public IntPtr AAD;                          // 指向附加驗證資料
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr CIPHER_TEXT_LENGTH;          // 密文長度
        public UIntPtr NONCE_LENGTH;                // 唯一值長度
        public UIntPtr TAG_LENGTH;                  // 認證標籤長度
        public UIntPtr AAD_LENGTH;                  // 附加驗證資料長度
    };

    // AES_WRAP_ENCRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_WRAP_ENCRYPT
    {
        public IntPtr KEY;                          // 指向密鑰
        public IntPtr KEK;                          // 指向包裝密鑰
        public IntPtr WRAP_KEY;                     // 指向已包裝密鑰輸出
        public UIntPtr KEY_LENGTH;                  // 密鑰長度
        public UIntPtr KEK_LENGTH;                  // 包裝密鑰長度 (16、24 或 32 位元組)
        public UIntPtr WRAP_KEY_LENGTH;             // 已包裝密鑰輸出長度
    };

    // AES_WRAP_DECRYPT
    [StructLayout(LayoutKind.Sequential)]
    public struct AES_WRAP_DECRYPT
    {
        public IntPtr WRAP_KEY;                     // 指向已包裝密鑰
        public IntPtr KEK;                          // 指向包裝密鑰
        public IntPtr KEY;                          // 指向解包密鑰的緩衝區
        public UIntPtr WRAP_KEY_LENGTH;             // 已包裝密鑰長度
        public UIntPtr KEK_LENGTH;                  // 包裝金鑰長度 (16、24 或 32 位元組)
        public UIntPtr KEY_LENGTH;                  // 解包密鑰的輸出長度
    };
}
