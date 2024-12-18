using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp.Command
{
    internal class HashIO
    {
        public static void MD5(string content, string salt, SALT_SEQUENCE seq)
        {
            try
            {
                Hash hash = new Hash();
                byte[] inputContent = hash.Import(content);
                byte[] inputSalt = hash.Import(salt);
                byte[] result = hash.MD5(inputContent, inputSalt, seq);

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Console.WriteLine(encoder.Encode<string>(result));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }
    }
}
