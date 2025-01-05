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
        HASH_NULL           = 0,
        HASH_MD5            = 1,
        HASH_MD5_SHA1       = 2,
        HASH_SHA1           = 3,
        HASH_SHA2_224       = 4,
        HASH_SHA2_256       = 5,
        HASH_SHA2_384       = 6,
        HASH_SHA2_512       = 7,
        HASH_SHA2_512_224   = 8,
        HASH_SHA2_512_256   = 9,
        HASH_SHA3_224       = 10,
        HASH_SHA3_256       = 11,
        HASH_SHA3_384       = 12,
        HASH_SHA3_512       = 13,
        HASH_SHA3_KE_128    = 14,
        HASH_SHA3_KE_256    = 15,
        HASH_BLAKE2S_256    = 16,
        HASH_BLAKE2B_512    = 17,
        HASH_SM3            = 18,
        HASH_RIPEMD160      = 19,
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
