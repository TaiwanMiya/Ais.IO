using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO
{
    public class BinaryIOException : Exception
    {
        public BinaryIOException() : base() { }

        public BinaryIOException(string? message) : base(message) { }
    }
}
