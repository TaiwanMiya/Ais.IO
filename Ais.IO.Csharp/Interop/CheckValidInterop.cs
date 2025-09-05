using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace Ais.IO.Csharp
{
    public static class CheckValidInterop
    {
#if DEBUG
        private const string DllName = "..\\Ais.IO.dll";
#else
        private const string DllName = "Ais.IO.dll";
#endif

        #region CheckValid.h
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool IsValidDNS(StringBuilder dns);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool IsValidIPv4(StringBuilder ip);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool IsValidIPv6(StringBuilder ip);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool IsValidEmail(StringBuilder email);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool IsValidURI(StringBuilder uri);
        #endregion
    }
}
