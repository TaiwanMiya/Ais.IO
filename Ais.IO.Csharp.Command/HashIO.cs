using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp.Command
{
    internal class HashIO
    {
        public static void Run(string content, string salt, HASH_TYPE type, SALT_SEQUENCE seq)
        {
            try
            {
                long length = 0;
                Hash hash = new Hash();
                byte[] inputContent = hash.Import(content);
                byte[] inputSalt = hash.Import(salt);
                if (type == HASH_TYPE.HASH_SHA3_KE_128)
                    length = 16;
                if (type == HASH_TYPE.HASH_SHA3_KE_256)
                    length = 32;
                byte[] result = hash.Do(inputContent, inputSalt, type, seq, length);

                BaseEncoding encoder = new BaseEncoding(EncodingType.Base16);
                Console.WriteLine(encoder.Encode<string>(result));
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }
    }
}
