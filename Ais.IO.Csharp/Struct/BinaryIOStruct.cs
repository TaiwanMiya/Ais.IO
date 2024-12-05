using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public enum BINARYIO_TYPE : byte
	{
        TYPE_NULL = 0,
        TYPE_BOOLEAN = 1,
		TYPE_BYTE = 2,
		TYPE_SBYTE = 3,
		TYPE_SHORT = 4,
		TYPE_USHORT = 5,
		TYPE_INT = 6,
		TYPE_UINT = 7,
		TYPE_LONG = 8,
		TYPE_ULONG = 9,
		TYPE_FLOAT = 10,
		TYPE_DOUBLE = 11,
		TYPE_BYTES = 12,
		TYPE_STRING = 13,
	};

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct BINARYIO_INDICES
    {
        public ulong POSITION;		// 對應 C++ 的 POSITION
        public BINARYIO_TYPE TYPE;  // 對應 C++ 的 TYPE
        public ulong LENGTH;		// 對應 C++ 的 LENGTH
    }
}
