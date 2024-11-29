using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public static class StructTInterop
    {
        private const string DllName = "..\\Ais.IO.dll";

        [StructLayout(LayoutKind.Sequential)]
        public struct MyStruct
        {
            public int id;
            public float value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WindowInfo
        {
            public int id;
            [MarshalAs(UnmanagedType.LPStr)]
            public string title;
        }

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ModifyStruct(ref MyStruct s);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void EnumCallback(ref WindowInfo window);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern void EnumWindowsMock(EnumCallback callback);

        public static EnumCallback Callback;
    }
}
