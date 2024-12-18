using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    // Hash Salt add sequence
    [Flags]
    public enum SALT_SEQUENCE
    {
        SALT_NULL   = 0,
        SALT_FIRST  = 1 << 0,
        SALT_LAST   = 1 << 1,
        SALT_MIDDLE = 1 << 2,
    };

    // Hash type options
    public enum HASH_TYPE
    {
        HASH_MD5            = 0,
        HASH_MD5_SHA1       = 1,
        HASH_SHA1           = 2,
        HASH_SHA2_224       = 3,
        HASH_SHA2_256       = 4,
        HASH_SHA2_384       = 5,
        HASH_SHA2_512       = 6,
        HASH_SHA2_512_224   = 7,
        HASH_SHA2_512_256   = 8,
        HASH_SHA3_224       = 9,
        HASH_SHA3_256       = 10,
        HASH_SHA3_384       = 11,
        HASH_SHA3_512       = 12,
        HASH_SHA3_KE_128    = 13,
        HASH_SHA3_KE_256    = 14,
        HASH_BLAKE2S_256    = 15,
        HASH_BLAKE2B_512    = 16,
        HASH_SM3            = 17,
        HASH_RIPEMD160      = 18,
     }

    // HASH_STRUCTURE
    public struct HASH_STRUCTURE
    {
        public IntPtr INPUT;
        public IntPtr SALT;
        public IntPtr OUTPUT;
	    public HASH_TYPE HASH_TYPE;
        public SALT_SEQUENCE SEQUENCE;
        public UIntPtr INPUT_LENGTH;
        public UIntPtr SALT_LENGTH;
        public UIntPtr OUTPUT_LENGTH;
    };
}
