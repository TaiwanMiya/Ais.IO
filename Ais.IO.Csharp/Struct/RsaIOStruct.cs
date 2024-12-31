using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RSA_PARAMETERS
    {
        public ulong KEY_LENGTH;
        public IntPtr N;
        public IntPtr E;
        public IntPtr D;
        public IntPtr P;
        public IntPtr Q;
        public IntPtr DP;
        public IntPtr DQ;
        public IntPtr QI;
        public ulong N_LENGTH;
        public ulong E_LENGTH;
        public ulong D_LENGTH;
        public ulong P_LENGTH;
        public ulong Q_LENGTH;
        public ulong DP_LENGTH;
        public ulong DQ_LENGTH;
        public ulong QI_LENGTH;
    }

    public struct RSA_KEY_PAIR
    {
        public UIntPtr KEY_SIZE;                // 金鑰建立長度
        public ASYMMETRIC_KEY_FORMAT FORMAT;    // 金鑰輸出格式
        public IntPtr PUBLIC_KEY;               // 指向公鑰數據
        public IntPtr PRIVATE_KEY;              // 指向私鑰數據
        public UIntPtr PUBLIC_KEY_LENGTH;       // 公鑰長度
        public UIntPtr PRIVATE_KEY_LENGTH;      // 私鑰長度
    }
}
