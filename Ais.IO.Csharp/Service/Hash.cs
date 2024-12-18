using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public class Hash : Asymmetric
    {
        public Hash() { }

        public byte[] MD5(byte[] input, byte[] salt, SALT_SEQUENCE seq)
        {
            byte[] output = new byte[input.Length];

            GCHandle inputHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
            GCHandle saltHandle = GCHandle.Alloc(salt, GCHandleType.Pinned);
            GCHandle outputHandle = GCHandle.Alloc(output, GCHandleType.Pinned);

            try
            {
                HASH_MD5 hash = new HASH_MD5
                {
                    INPUT = inputHandle.AddrOfPinnedObject(),
                    SALT = saltHandle.AddrOfPinnedObject(),
                    OUTPUT = outputHandle.AddrOfPinnedObject(),
                    SEQUENCE = seq,
                    INPUT_LENGTH = (UIntPtr)input.Length,
                    SALT_LENGTH = (UIntPtr)salt.Length,
                };
                int outputLength = HashInterop.HashMd5(ref hash);
                if (outputLength > 0)
                {
                    byte[] result = new byte[outputLength];
                    Array.Copy(output, result, outputLength);
                    output = result;
                }
                else
                    output = new byte[0];
                return output;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (inputHandle.IsAllocated) inputHandle.Free();
                if (saltHandle.IsAllocated) saltHandle.Free();
                if (outputHandle.IsAllocated) outputHandle.Free();
            }
        }
    }
}
