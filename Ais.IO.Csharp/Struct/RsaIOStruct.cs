using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public struct RSA_PARAMETERS
    {
        public UIntPtr KEY_SIZE;

        public IntPtr MODULUS;
        public UIntPtr MODULUS_LENGTH;

        public IntPtr PUBLIC_EXPONENT;
        public UIntPtr PUBLIC_EXPONENT_LENGTH;

        public IntPtr PRIVATE_EXPONENT;
        public UIntPtr PRIVATE_EXPONENT_LENGTH;

        public IntPtr PRIME1;
        public UIntPtr PRIME1_LENGTH;

        public IntPtr PRIME2;
        public UIntPtr PRIME2_LENGTH;

        public IntPtr EXPONENT1;
        public UIntPtr EXPONENT1_LENGTH;

        public IntPtr EXPONENT2;
        public UIntPtr EXPONENT2_LENGTH;

        public IntPtr COEFFICIENT;
        public UIntPtr COEFFICIENT_LENGTH;
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
