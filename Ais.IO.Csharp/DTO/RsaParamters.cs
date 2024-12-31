using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public class RsaParamters
    {
        public byte[] N { get; set; }
        public byte[] E { get; set; }
        public byte[] D { get; set; }
        public byte[] P { get; set; }
        public byte[] Q { get; set; }
        public byte[] DP { get; set; }
        public byte[] DQ { get; set; }
        public byte[] QI { get; set; }
    }
}
