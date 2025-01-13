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
        public static extern long Base10Length(long inputSize, bool isEncode);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Base16Length(long inputSize, bool isEncode);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Base32Length(long inputSize, bool isEncode);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Base58Length(long inputSize, bool isEncode);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Base62Length(long inputSize, bool isEncode);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Base64Length(long inputSize, bool isEncode);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Base85Length(long inputSize, bool isEncode);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Base91Length(long inputSize, bool isEncode);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Base128Length(long inputSize, bool isEncode);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base10Encode(byte[] input, long inputSize, StringBuilder output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base10Decode(StringBuilder input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base16Encode(byte[] input, long inputSize, StringBuilder output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base16Decode(StringBuilder input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base32Encode(byte[] input, long inputSize, StringBuilder output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base32Decode(StringBuilder input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base58Encode(byte[] input, long inputSize, StringBuilder output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base58Decode(StringBuilder input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base62Encode(byte[] input, long inputSize, StringBuilder output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base62Decode(StringBuilder input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base64Encode(byte[] input, long inputSize, StringBuilder output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base64Decode(StringBuilder input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base85Encode(byte[] input, long inputSize, StringBuilder output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base85Decode(StringBuilder input, long inputSize, byte[] output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base91Encode(byte[] input, long inputSize, StringBuilder output, long outputSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Base91Decode(StringBuilder input, long inputSize, byte[] output, long outputSize);
        #endregion
    }
}
