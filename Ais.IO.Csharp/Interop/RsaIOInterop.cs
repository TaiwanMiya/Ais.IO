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
#if DEBUG
        private const string DllName = "..\\Ais.IO.dll";
#else
        private const string DllName = "Ais.IO.dll";
#endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RsaGetParametersLength(ref RSA_PARAMETERS @params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RsaGetKeyLength(ref RSA_KEY_PAIR @params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RsaGenerateParameters(ref RSA_PARAMETERS @params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RsaGenerateKeys(ref RSA_KEY_PAIR encryption);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RsaExportParameters(ref EXPORT_RSA @params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RsaExportKeys(ref EXPORT_RSA @params);
    }
}
