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
#if DEBUG
        private const string DllName = "..\\Ais.IO.dll";
#else
        private const string DllName = "Ais.IO.dll";
#endif

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
