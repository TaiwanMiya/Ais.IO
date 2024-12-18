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

        public byte[] Do(byte[] input, byte[] salt, HASH_TYPE type, SALT_SEQUENCE seq, long length = 0)
        {
            int hashOutputLength = HashInterop.GetHashLength(type);
            byte[] output = new byte[hashOutputLength == -1 ? length: hashOutputLength];

            GCHandle inputHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
            GCHandle saltHandle = GCHandle.Alloc(salt, GCHandleType.Pinned);
            GCHandle outputHandle = GCHandle.Alloc(output, GCHandleType.Pinned);

            try
            {
                HASH_STRUCTURE hash = new HASH_STRUCTURE
                {
                    INPUT = inputHandle.AddrOfPinnedObject(),
                    SALT = saltHandle.AddrOfPinnedObject(),
                    OUTPUT = outputHandle.AddrOfPinnedObject(),
                    HASH_TYPE = type,
                    SEQUENCE = seq,
                    INPUT_LENGTH = (UIntPtr)input.Length,
                    SALT_LENGTH = (UIntPtr)salt.Length,
                    OUTPUT_LENGTH = (UIntPtr)length,
                };
                int outputLength = HashInterop.Hash(ref hash);
                if (outputLength > 0)
                {
                    byte[] result = new byte[hashOutputLength == -1 ? length : hashOutputLength];
                    Array.Copy(output, result, hashOutputLength == -1 ? length : hashOutputLength);
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
