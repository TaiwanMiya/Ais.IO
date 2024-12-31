using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public static class RsaIOInterop
    {
        private const string DllName = "..\\Ais.IO.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GetRsaParametersLength(ref RSA_PARAMETERS @params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GetRsaKeyLength(ref RSA_KEY_PAIR @params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateRsaParameters(ref RSA_PARAMETERS @params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateRsaKeys(ref RSA_KEY_PAIR encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ExportRsaParametersFromKeys(ref EXPORT_RSA_PARAMTERS @params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ExportRsaKeysFromParameters(ref EXPORT_RSA_KEY @params);
    }
}
