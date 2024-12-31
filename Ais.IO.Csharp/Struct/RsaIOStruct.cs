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
        public ulong KEY_LENGTH;    // 金鑰長度
        public IntPtr N;            // 指向模數 (Modulus)
        public IntPtr E;            // 指向公鑰指數 (Public Exponent)
        public IntPtr D;            // 指向私鑰指數 (Private Exponent)
        public IntPtr P;            // 指向質數1 (First Prime Factor)
        public IntPtr Q;            // 指向質數2 (Second Prime Factor)
        public IntPtr DP;           // 指向模1私鑰指數 (First CRT Exponent)
        public IntPtr DQ;           // 指向模2私鑰指數 (Second CRT Exponent)
        public IntPtr QI;           // 指向模逆 (CRT Coefficient)
        public ulong N_LENGTH;      // 模數 (Modulus) 長度
        public ulong E_LENGTH;      // 公鑰指數 (Public Exponent) 長度
        public ulong D_LENGTH;      // 私鑰指數 (Private Exponent) 長度
        public ulong P_LENGTH;      // 質數1 (First Prime Factor) 長度
        public ulong Q_LENGTH;      // 質數2 (Second Prime Factor) 長度
        public ulong DP_LENGTH;     // 模1私鑰指數 (First CRT Exponent) 長度
        public ulong DQ_LENGTH;     // 模2私鑰指數 (Second CRT Exponent) 長度
        public ulong QI_LENGTH;     // 模逆 (CRT Coefficient) 長度
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RSA_KEY_PAIR
    {
        public ulong KEY_LENGTH;                    // 金鑰長度
        public ASYMMETRIC_KEY_FORMAT KEY_FORMAT;    // 金鑰格式
        public IntPtr PUBLIC_KEY;                   // 指向公鑰數據
        public IntPtr PRIVATE_KEY;                  // 指向私鑰數據
        public ulong PUBLIC_KEY_LENGTH;             // 公鑰長度
        public ulong PRIVATE_KEY_LENGTH;            // 私鑰長度
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXPORT_RSA
    {
        public ulong KEY_LENGTH;                    // 金鑰長度
        public ASYMMETRIC_KEY_FORMAT KEY_FORMAT;    // 金鑰格式
        public IntPtr N;                            // 指向模數 (Modulus)
        public IntPtr E;                            // 指向公鑰指數 (Public Exponent)
        public IntPtr D;                            // 指向私鑰指數 (Private Exponent)
        public IntPtr P;                            // 指向質數1 (First Prime Factor)
        public IntPtr Q;                            // 指向質數2 (Second Prime Factor)
        public IntPtr DP;                           // 指向模1私鑰指數 (First CRT Exponent)
        public IntPtr DQ;                           // 指向模2私鑰指數 (Second CRT Exponent)
        public IntPtr QI;                           // 指向模逆 (CRT Coefficient)
        public ulong N_LENGTH;                      // 模數 (Modulus) 長度
        public ulong E_LENGTH;                      // 公鑰指數 (Public Exponent) 長度
        public ulong D_LENGTH;                      // 私鑰指數 (Private Exponent) 長度
        public ulong P_LENGTH;                      // 質數1 (First Prime Factor) 長度
        public ulong Q_LENGTH;                      // 質數2 (Second Prime Factor) 長度
        public ulong DP_LENGTH;                     // 模1私鑰指數 (First CRT Exponent) 長度
        public ulong DQ_LENGTH;                     // 模2私鑰指數 (Second CRT Exponent) 長度
        public ulong QI_LENGTH;                     // 模逆 (CRT Coefficient) 長度
        public IntPtr PUBLIC_KEY;                   // 指向公鑰數據
        public IntPtr PRIVATE_KEY;                  // 指向私鑰數據
        public ulong PUBLIC_KEY_LENGTH;             // 公鑰長度
        public ulong PRIVATE_KEY_LENGTH;            // 私鑰長度
    };
}
