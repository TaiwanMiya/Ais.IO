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
        public static extern int GenerateRsaParameters(ref RSA_PARAMETERS @params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RsaGenerate(ref RSA_KEY_PAIR encryption);
    }
}
