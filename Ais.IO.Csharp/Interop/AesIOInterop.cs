using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public static class AesIOInterop
    {
        private const string DllName = "..\\Ais.IO.dll";

        // Import GenerateKey function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateKey(byte[] key, long keyLength);

        // Import GenerateIV function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateIV(byte[] iv, long ivLength);

        // Import GenerateKeyFromInput function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateKeyFromInput(byte[] input, long inputLength, byte[] key, long keyLength);
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateKeyFromInput(string input, long inputLength, byte[] key, long keyLength);

        // Import GenerateIVFromInput function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateIVFromInput(byte[] input, long inputLength, byte[] iv, long ivLength);
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateIVFromInput(string input, long inputLength, byte[] iv, long ivLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesCtrEncrypt(ref AES_CTR_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesCtrDecrypt(ref AES_CTR_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesCbcEncrypt(ref AES_CBC_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesCbcDecrypt(ref AES_CBC_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesCfbEncrypt(ref AES_CFB_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesCfbDecrypt(ref AES_CFB_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesOfbEncrypt(ref AES_OFB_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesOfbDecrypt(ref AES_OFB_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesEcbEncrypt(ref AES_ECB_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesEcbDecrypt(ref AES_ECB_DECRYPT decryption);
    }
}
