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

        // Import GenerateTag function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateTag(byte[] tag, long tagLength);

        // Import GenerateAad function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateAad(byte[] aad, long aadLength);

        // Import GenerateTweak function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateTweak(byte[] tweak, long tweakLength);

        // Import ImportKey function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ImportKey(byte[] input, long inputLength, byte[] key, long keyLength);
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ImportKey(string input, long inputLength, byte[] key, long keyLength);

        // Import ImportIV function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ImportIV(byte[] input, long inputLength, byte[] iv, long ivLength);
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ImportIV(string input, long inputLength, byte[] iv, long ivLength);

        // Import ImportTag function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ImportTag(byte[] input, long inputLength, byte[] tag, long tagLength);
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ImportTag(string input, long inputLength, byte[] tag, long tagLength);

        // Import ImportAad function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ImportAad(byte[] input, long inputLength, byte[] aad, long aadLength);
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ImportAad(string input, long inputLength, byte[] aad, long aadLength);

        // Import ImportTweak function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ImportTweak(byte[] input, long inputLength, byte[] tweak, long tweakLength);
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ImportTweak(string input, long inputLength, byte[] tweak, long tweakLength);

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

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesGcmEncrypt(ref AES_GCM_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesGcmDecrypt(ref AES_GCM_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesCcmEncrypt(ref AES_CCM_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesCcmDecrypt(ref AES_CCM_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesXtsEncrypt(ref AES_XTS_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesXtsDecrypt(ref AES_XTS_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesOcbEncrypt(ref AES_OCB_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesOcbDecrypt(ref AES_OCB_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesWrapEncrypt(ref AES_WRAP_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int AesWrapDecrypt(ref AES_WRAP_DECRYPT decryption);
    }
}
