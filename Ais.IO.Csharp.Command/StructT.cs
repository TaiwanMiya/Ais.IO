using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Ais.IO.Csharp;

namespace Ais.IO.Csharp.Command
{
    internal class StructT
    {
        public static void GetStruct()
        {
            StructTInterop.MyStruct myStruct = new StructTInterop.MyStruct { id = 1, value = 1.5f };
            Console.WriteLine($"Before: id={myStruct.id}, value={myStruct.value}");

            StructTInterop.ModifyStruct(ref myStruct);

            Console.WriteLine($"After: id={myStruct.id}, value={myStruct.value}");

            StructTInterop.Callback = (ref StructTInterop.WindowInfo window) => Console.WriteLine($"Window ID: {window.id}, Title: {window.title}");
            StructTInterop.EnumWindowsMock(StructTInterop.Callback);
        }
    }
}
