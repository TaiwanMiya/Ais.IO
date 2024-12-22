using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public class Symmetry
    {
        public Symmetry() { }

        public byte[] Generate(int size)
        {
            byte[] content = new byte[size];
            SymmetryIOInterop.Generate(content, size);
            return content;
        }

        public byte[] Import(string content)
        {
            byte[] output = new byte[content.Length];
            SymmetryIOInterop.Import(content, content.Length, output, output.Length);
            return output;
        }
    }
}
