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
        public RsaParamters GenerateParamters(ulong size)
        {
            byte[] n = new byte[0];
            byte[] e = new byte[0];
            byte[] d = new byte[0];
            byte[] p = new byte[0];
            byte[] q = new byte[0];
            byte[] dp = new byte[0];
            byte[] dq = new byte[0];
            byte[] qi = new byte[0];

            GCHandle nHandle = GCHandle.Alloc(n, GCHandleType.Pinned);
            GCHandle eHandle = GCHandle.Alloc(e, GCHandleType.Pinned);
            GCHandle dHandle = GCHandle.Alloc(d, GCHandleType.Pinned);
            GCHandle pHandle = GCHandle.Alloc(p, GCHandleType.Pinned);
            GCHandle qHandle = GCHandle.Alloc(q, GCHandleType.Pinned);
            GCHandle dpHandle = GCHandle.Alloc(dp, GCHandleType.Pinned);
            GCHandle dqHandle = GCHandle.Alloc(dq, GCHandleType.Pinned);
            GCHandle qiHandle = GCHandle.Alloc(qi, GCHandleType.Pinned);
            try
            {
                RSA_PARAMETERS paramters = new RSA_PARAMETERS
                {
                    KEY_LENGTH = (ulong)size,
                    N = IntPtr.Zero,
                    E = IntPtr.Zero,
                    D = IntPtr.Zero,
                    P = IntPtr.Zero,
                    Q = IntPtr.Zero,
                    DP = IntPtr.Zero,
                    DQ = IntPtr.Zero,
                    QI = IntPtr.Zero,
                    N_LENGTH = 0,
                    E_LENGTH = 0,
                    D_LENGTH = 0,
                    P_LENGTH = 0,
                    Q_LENGTH = 0,
                    DP_LENGTH = 0,
                    DQ_LENGTH = 0,
                    QI_LENGTH = 0,
                };
                RsaIOInterop.GetRsaParametersLength(ref paramters);

                n = new byte[paramters.N_LENGTH];
                e = new byte[paramters.E_LENGTH];
                d = new byte[paramters.D_LENGTH];
                p = new byte[paramters.P_LENGTH];
                q = new byte[paramters.Q_LENGTH];
                dp = new byte[paramters.DP_LENGTH];
                dq = new byte[paramters.DQ_LENGTH];
                qi = new byte[paramters.QI_LENGTH];

                nHandle = GCHandle.Alloc(n, GCHandleType.Pinned);
                eHandle = GCHandle.Alloc(e, GCHandleType.Pinned);
                dHandle = GCHandle.Alloc(d, GCHandleType.Pinned);
                pHandle = GCHandle.Alloc(p, GCHandleType.Pinned);
                qHandle = GCHandle.Alloc(q, GCHandleType.Pinned);
                dpHandle = GCHandle.Alloc(dp, GCHandleType.Pinned);
                dqHandle = GCHandle.Alloc(dq, GCHandleType.Pinned);
                qiHandle = GCHandle.Alloc(qi, GCHandleType.Pinned);

                paramters.N = nHandle.AddrOfPinnedObject();
                paramters.E = eHandle.AddrOfPinnedObject();
                paramters.D = dHandle.AddrOfPinnedObject();
                paramters.P = pHandle.AddrOfPinnedObject();
                paramters.Q = qHandle.AddrOfPinnedObject();
                paramters.DP = dpHandle.AddrOfPinnedObject();
                paramters.DQ = dqHandle.AddrOfPinnedObject();
                paramters.QI = qiHandle.AddrOfPinnedObject();

                int result = RsaIOInterop.GenerateRsaParameters(ref paramters);
                if (result != 0)
                    throw new Exception("Error Get Paramters.");

                return new RsaParamters()
                {
                    N = n,
                    E = e,
                    D = d,
                    P = p,
                    Q = q,
                    DP = dp,
                    DQ = dq,
                    QI = qi,
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                return null;
            }
            finally
            {
                if (nHandle.IsAllocated) nHandle.Free();
                if (eHandle.IsAllocated) eHandle.Free();
                if (dHandle.IsAllocated) dHandle.Free();
                if (pHandle.IsAllocated) pHandle.Free();
                if (qHandle.IsAllocated) qHandle.Free();
                if (dpHandle.IsAllocated) dpHandle.Free();
                if (dqHandle.IsAllocated) dqHandle.Free();
                if (qiHandle.IsAllocated) qiHandle.Free();
            }

            //byte[] Modulus = new byte[size / 8];
            //byte[] PublicExponent = new byte[3];
            //byte[] PrivateExponent = new byte[size / 8];
            //byte[] Prime1 = new byte[size / 16];
            //byte[] Prime2 = new byte[size / 16];
            //byte[] Exponent1 = new byte[size / 16];
            //byte[] Exponent2 = new byte[size / 16];
            //byte[] Coefficient = new byte[size / 16];

            //GCHandle ModulusHandle = GCHandle.Alloc(Modulus, GCHandleType.Pinned);
            //GCHandle PublicExponentHandle = GCHandle.Alloc(PublicExponent, GCHandleType.Pinned);
            //GCHandle PrivateExponentHandle = GCHandle.Alloc(PrivateExponent, GCHandleType.Pinned);
            //GCHandle Prime1Handle = GCHandle.Alloc(Prime1, GCHandleType.Pinned);
            //GCHandle Prime2Handle = GCHandle.Alloc(Prime2, GCHandleType.Pinned);
            //GCHandle Exponent1Handle = GCHandle.Alloc(Exponent1, GCHandleType.Pinned);
            //GCHandle Exponent2Handle = GCHandle.Alloc(Exponent2, GCHandleType.Pinned);
            //GCHandle CoefficientHandle = GCHandle.Alloc(Coefficient, GCHandleType.Pinned);

            //try
            //{
            //    RSA_PARAMETERS paramters = new RSA_PARAMETERS
            //    {
            //        KEY_SIZE = (UIntPtr)size,
            //        MODULUS = ModulusHandle.AddrOfPinnedObject(),
            //        MODULUS_LENGTH = new UIntPtr((uint)size / 8),
            //        PUBLIC_EXPONENT = PublicExponentHandle.AddrOfPinnedObject(),
            //        PUBLIC_EXPONENT_LENGTH = new UIntPtr(3),
            //        PRIVATE_EXPONENT = PrivateExponentHandle.AddrOfPinnedObject(),
            //        PRIVATE_EXPONENT_LENGTH = new UIntPtr((uint)size / 8),
            //        PRIME1 = Prime1Handle.AddrOfPinnedObject(),
            //        PRIME1_LENGTH = new UIntPtr((uint)size / 16),
            //        PRIME2 = Prime2Handle.AddrOfPinnedObject(),
            //        PRIME2_LENGTH = new UIntPtr((uint)size / 16),
            //        EXPONENT1 = Exponent1Handle.AddrOfPinnedObject(),
            //        EXPONENT1_LENGTH = new UIntPtr((uint)size / 16),
            //        EXPONENT2 = Exponent2Handle.AddrOfPinnedObject(),
            //        EXPONENT2_LENGTH = new UIntPtr((uint)size / 16),
            //        COEFFICIENT = CoefficientHandle.AddrOfPinnedObject(),
            //        COEFFICIENT_LENGTH = new UIntPtr((uint)size / 16),
            //    };
            //    int result = RsaIOInterop.GenerateRsaParameters(ref paramters);
            //    if (result != 0)
            //        throw new Exception("Error Get Paramters.");
            //}
            //catch (Exception ex)
            //{
            //    Console.WriteLine("Error: " + ex.Message);
            //}
            //finally
            //{
            //    if (ModulusHandle.IsAllocated) ModulusHandle.Free();
            //    if (PublicExponentHandle.IsAllocated) PublicExponentHandle.Free();
            //    if (PrivateExponentHandle.IsAllocated) PrivateExponentHandle.Free();
            //    if (Prime1Handle.IsAllocated) Prime1Handle.Free();
            //    if (Prime2Handle.IsAllocated) Prime2Handle.Free();
            //    if (Exponent1Handle.IsAllocated) Exponent1Handle.Free();
            //    if (Exponent2Handle.IsAllocated) Exponent2Handle.Free();
            //    if (CoefficientHandle.IsAllocated) CoefficientHandle.Free();
            //}
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
