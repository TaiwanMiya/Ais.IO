using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public class Asymmetric
    {
        public Asymmetric() { }

        public byte[] Generate(int size)
        {
            byte[] content = new byte[size];
            AsymmetricIOInterop.Generate(content, size);
            return content;
        }

        public byte[] Import(string content)
        {
            byte[] output = new byte[content.Length];
            AsymmetricIOInterop.Import(content, content.Length, output, output.Length);
            return output;
        }
    }
}
