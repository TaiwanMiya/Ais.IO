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

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateKey(byte[] key, int keyLength);

        // Import GenerateIV function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateIV(byte[] iv, int ivLength);

        // Import GenerateKeyFromInput function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateKeyFromInput(string input, byte[] key, int keyLength);

        // Import GenerateIVFromInput function from the DLL
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GenerateIVFromInput(string input, byte[] iv, int ivLength);
    }
}
