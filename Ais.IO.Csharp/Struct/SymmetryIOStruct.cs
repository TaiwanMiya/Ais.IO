using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    // CFB - SEGMENT_SIZE
    public enum SEGMENT_SIZE_OPTION
    {
        SEGMENT_1_BIT = 1,
        SEGMENT_8_BIT = 8,
        SEGMENT_64_BIT = 64,
        SEGMENT_128_BIT = 128,
    }

    // RSA - PEM Private Key Crypter
    public enum SYMMETRY_CRYPTER
    {
        SYMMETRY_NULL = 0,
        SYMMETRY_AES_CTR = 1,
        SYMMETRY_AES_CBC = 2,
        SYMMETRY_AES_CFB = 3,
        SYMMETRY_AES_OFB = 4,
        SYMMETRY_AES_ECB = 5,
        SYMMETRY_AES_GCM = 6,
        SYMMETRY_AES_CCM = 7,
        SYMMETRY_AES_XTS = 8,
        SYMMETRY_AES_OCB = 9,
        SYMMETRY_AES_WRAP = 10,
        SYMMETRY_DES_CBC = 11,
        SYMMETRY_DES_CFB = 12,
        SYMMETRY_DES_OFB = 13,
        SYMMETRY_DES_ECB = 14,
        SYMMETRY_DES_WRAP = 15,
    }
}
