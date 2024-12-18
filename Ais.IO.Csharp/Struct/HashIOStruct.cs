using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    // Hash Salt add sequence
    public enum SALT_SEQUENCE
    {
        SALT_NULL = 0,
        SALT_FIRST = 1,
        SALT_LAST = 2,
    };

    // HASH_MD5
    public struct HASH_MD5
    {
        public IntPtr INPUT;
        public IntPtr SALT;
        public IntPtr OUTPUT;
        public SALT_SEQUENCE SEQUENCE;
        public UIntPtr INPUT_LENGTH;
        public UIntPtr SALT_LENGTH;
    };
}
