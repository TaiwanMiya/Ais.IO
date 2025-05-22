using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public static class DesIOInterop
    {
#if DEBUG
        private const string DllName = "..\\Ais.IO.dll";
#else
        private const string DllName = "Ais.IO.dll";
#endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int DesCbcEncrypt(ref DES_CBC_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int DesCbcDecrypt(ref DES_CBC_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int DesCfbEncrypt(ref DES_CFB_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int DesCfbDecrypt(ref DES_CFB_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int DesOfbEncrypt(ref DES_OFB_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int DesOfbDecrypt(ref DES_OFB_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int DesEcbEncrypt(ref DES_ECB_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int DesEcbDecrypt(ref DES_ECB_DECRYPT decryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int DesWrapEncrypt(ref DES_WRAP_ENCRYPT encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int DesWrapDecrypt(ref DES_WRAP_DECRYPT decryption);
    }
}
