using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public static class AsymmetricIOInterop
    {
        private const string DllName = "..\\Ais.IO.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Generate(byte[] content, long length);

        // Import ImportKey function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Import(byte[] input, long inputLength, byte[] output, long outputLength);
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Import(string input, long inputLength, byte[] output, long outputLength);
    }
}
