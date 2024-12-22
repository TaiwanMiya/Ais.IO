using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public class Rsa : Asymmetric
    {
        public void GenerateParamters(int size)
        {
            byte[] Modulus = new byte[size / 8];
            byte[] PublicExponent = new byte[3];
            byte[] PrivateExponent = new byte[size / 8];
            byte[] Prime1 = new byte[size / 16];
            byte[] Prime2 = new byte[size / 16];
            byte[] Exponent1 = new byte[size / 16];
            byte[] Exponent2 = new byte[size / 16];
            byte[] Coefficient = new byte[size / 16];

            GCHandle ModulusHandle = GCHandle.Alloc(Modulus, GCHandleType.Pinned);
            GCHandle PublicExponentHandle = GCHandle.Alloc(PublicExponent, GCHandleType.Pinned);
            GCHandle PrivateExponentHandle = GCHandle.Alloc(PrivateExponent, GCHandleType.Pinned);
            GCHandle Prime1Handle = GCHandle.Alloc(Prime1, GCHandleType.Pinned);
            GCHandle Prime2Handle = GCHandle.Alloc(Prime2, GCHandleType.Pinned);
            GCHandle Exponent1Handle = GCHandle.Alloc(Exponent1, GCHandleType.Pinned);
            GCHandle Exponent2Handle = GCHandle.Alloc(Exponent2, GCHandleType.Pinned);
            GCHandle CoefficientHandle = GCHandle.Alloc(Coefficient, GCHandleType.Pinned);

            try
            {
                RSA_PARAMETERS paramters = new RSA_PARAMETERS
                {
                    KEY_SIZE = (UIntPtr)size,
                    MODULUS = ModulusHandle.AddrOfPinnedObject(),
                    MODULUS_LENGTH = new UIntPtr((uint)size / 8),
                    PUBLIC_EXPONENT = PublicExponentHandle.AddrOfPinnedObject(),
                    PUBLIC_EXPONENT_LENGTH = new UIntPtr(3),
                    PRIVATE_EXPONENT = PrivateExponentHandle.AddrOfPinnedObject(),
                    PRIVATE_EXPONENT_LENGTH = new UIntPtr((uint)size / 8),
                    PRIME1 = Prime1Handle.AddrOfPinnedObject(),
                    PRIME1_LENGTH = new UIntPtr((uint)size / 16),
                    PRIME2 = Prime2Handle.AddrOfPinnedObject(),
                    PRIME2_LENGTH = new UIntPtr((uint)size / 16),
                    EXPONENT1 = Exponent1Handle.AddrOfPinnedObject(),
                    EXPONENT1_LENGTH = new UIntPtr((uint)size / 16),
                    EXPONENT2 = Exponent2Handle.AddrOfPinnedObject(),
                    EXPONENT2_LENGTH = new UIntPtr((uint)size / 16),
                    COEFFICIENT = CoefficientHandle.AddrOfPinnedObject(),
                    COEFFICIENT_LENGTH = new UIntPtr((uint)size / 16),
                };
                int result = RsaIOInterop.GenerateRsaParameters(ref paramters);
                if (result != 0)
                    throw new Exception("Error Get Paramters.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                if (ModulusHandle.IsAllocated) ModulusHandle.Free();
                if (PublicExponentHandle.IsAllocated) PublicExponentHandle.Free();
                if (PrivateExponentHandle.IsAllocated) PrivateExponentHandle.Free();
                if (Prime1Handle.IsAllocated) Prime1Handle.Free();
                if (Prime2Handle.IsAllocated) Prime2Handle.Free();
                if (Exponent1Handle.IsAllocated) Exponent1Handle.Free();
                if (Exponent2Handle.IsAllocated) Exponent2Handle.Free();
                if (CoefficientHandle.IsAllocated) CoefficientHandle.Free();
            }
        }

        public void Generate(int size, ASYMMETRIC_KEY_FORMAT format, ref byte[] publicKey, ref byte[] privateKey)
        {
            RSA_KEY_PAIR keypair = new RSA_KEY_PAIR
            {
                KEY_SIZE = (UIntPtr)size,
                FORMAT = format,
                PUBLIC_KEY = IntPtr.Zero,
                PRIVATE_KEY = IntPtr.Zero,
                PUBLIC_KEY_LENGTH = UIntPtr.Zero,
                PRIVATE_KEY_LENGTH = UIntPtr.Zero,
            };

            // Get Key Length
            int result = RsaIOInterop.RsaGenerate(ref keypair);
            if (result != 0)
            {
                publicKey = new byte[0];
                privateKey = new byte[0];
                return;
            }

            publicKey = new byte[(int)keypair.PUBLIC_KEY_LENGTH];
            privateKey = new byte[(int)keypair.PRIVATE_KEY_LENGTH];

            GCHandle publicKeyHandle = GCHandle.Alloc(publicKey, GCHandleType.Pinned);
            GCHandle privateKeyHandle = GCHandle.Alloc(privateKey, GCHandleType.Pinned);

            try
            {
                // Generate Key
                keypair.PUBLIC_KEY = publicKeyHandle.AddrOfPinnedObject();
                keypair.PRIVATE_KEY = privateKeyHandle.AddrOfPinnedObject();

                result = RsaIOInterop.RsaGenerate(ref keypair);
                if (result != 0)
                {
                    publicKey = new byte[0];
                    privateKey = new byte[0];
                }
            }
            finally
            {
                if (publicKeyHandle.IsAllocated) publicKeyHandle.Free();
                if (privateKeyHandle.IsAllocated) privateKeyHandle.Free();
            }
        }
    }
}
