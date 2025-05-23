﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public static class HashInterop
    {
#if DEBUG
        private const string DllName = "..\\Ais.IO.dll";
#else
        private const string DllName = "Ais.IO.dll";
#endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Hash(ref HASH_STRUCTURE hash);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GetHashLength(HASH_TYPE hash);
    }
}
