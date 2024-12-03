using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public static class EncoderIOInterop
    {
        private const string DllName = "..\\Ais.IO.dll";

        #region EncoderIO.h
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base16Encode(byte[] input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base16Decode(byte[] input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base32Encode(byte[] input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base32Decode(byte[] input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base64Encode(byte[] input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base64Decode(byte[] input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base85Encode(byte[] input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base85Decode(byte[] input, long inputSize, byte[] output, long outputSize);
        #endregion
    }
}
