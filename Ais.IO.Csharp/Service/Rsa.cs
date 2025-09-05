using Microsoft.SqlServer.Server;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Ais.IO.Csharp
{
    public class Rsa : Asymmetric
    {
        public RsaParamters CreateEmptyParamters(ulong size)
        {
            try
            {
                RSA_PARAMETERS paramters = new RSA_PARAMETERS
                {
                    KEY_LENGTH = size,
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
                int result = RsaIOInterop.RsaGetParametersLength(ref paramters);
                if (result == 0)
                    return new RsaParamters()
                    {
                        N = new byte[paramters.N_LENGTH],
                        E = new byte[paramters.E_LENGTH],
                        D = new byte[paramters.D_LENGTH],
                        P = new byte[paramters.P_LENGTH],
                        Q = new byte[paramters.Q_LENGTH],
                        DP = new byte[paramters.DP_LENGTH],
                        DQ = new byte[paramters.DQ_LENGTH],
                        QI = new byte[paramters.QI_LENGTH],
                    };
                else
                    return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                return null;
            }
        }

        public ulong GetKeyLength(ASYMMETRIC_KEY_FORMAT format, byte[] publicKey, byte[] privateKey, byte[] pemPassword = null, SYMMETRY_CRYPTER crypter = SYMMETRY_CRYPTER.SYMMETRY_AES_CBC, int cryptsize = 256, SEGMENT_SIZE_OPTION segment = SEGMENT_SIZE_OPTION.SEGMENT_128_BIT)
        {
            GCHandle publicKeyHandle = GCHandle.Alloc(publicKey, GCHandleType.Pinned);
            GCHandle privateKeyHandle = GCHandle.Alloc(privateKey, GCHandleType.Pinned);
            GCHandle pemPasswordHandle = GCHandle.Alloc(pemPassword, GCHandleType.Pinned);

            try
            {
                RSA_KEY_PAIR keypair = new RSA_KEY_PAIR
                {
                    KEY_LENGTH = 0,
                    KEY_FORMAT = format,
                    PUBLIC_KEY = publicKeyHandle.AddrOfPinnedObject(),
                    PRIVATE_KEY = privateKeyHandle.AddrOfPinnedObject(),
                    PEM_PASSWORD = pemPasswordHandle.AddrOfPinnedObject(),
                    PUBLIC_KEY_LENGTH = (ulong)publicKey.LongLength,
                    PRIVATE_KEY_LENGTH = (ulong)privateKey.LongLength,
                    PEM_PASSWORD_LENGTH = pemPassword == null ? 0 : (ulong)pemPassword.LongLength,
                    PEM_CIPHER = crypter,
                    PEM_CIPHER_SIZE = cryptsize,
                    PEM_CIPHER_SEGMENT = segment,
                };
                int result = RsaIOInterop.RsaGetKeyLength(ref keypair);
                if (result != 0)
                    throw new Exception("Error Get Key Length.");
                return keypair.KEY_LENGTH;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                return 0;
            }
            finally
            {
                if (publicKeyHandle.IsAllocated) publicKeyHandle.Free();
                if (privateKeyHandle.IsAllocated) privateKeyHandle.Free();
            }
        }

        public RsaParamters GenerateParamters(ulong size)
        {
            RsaParamters output = this.CreateEmptyParamters(size);
            if (output == null)
                return output;

            GCHandle nHandle = GCHandle.Alloc(output.N, GCHandleType.Pinned);
            GCHandle eHandle = GCHandle.Alloc(output.E, GCHandleType.Pinned);
            GCHandle dHandle = GCHandle.Alloc(output.D, GCHandleType.Pinned);
            GCHandle pHandle = GCHandle.Alloc(output.P, GCHandleType.Pinned);
            GCHandle qHandle = GCHandle.Alloc(output.Q, GCHandleType.Pinned);
            GCHandle dpHandle = GCHandle.Alloc(output.DP, GCHandleType.Pinned);
            GCHandle dqHandle = GCHandle.Alloc(output.DQ, GCHandleType.Pinned);
            GCHandle qiHandle = GCHandle.Alloc(output.QI, GCHandleType.Pinned);
            try
            {
                RSA_PARAMETERS paramters = new RSA_PARAMETERS
                {
                    KEY_LENGTH = size,
                    N = nHandle.AddrOfPinnedObject(),
                    E = eHandle.AddrOfPinnedObject(),
                    D = dHandle.AddrOfPinnedObject(),
                    P = pHandle.AddrOfPinnedObject(),
                    Q = qHandle.AddrOfPinnedObject(),
                    DP = dpHandle.AddrOfPinnedObject(),
                    DQ = dqHandle.AddrOfPinnedObject(),
                    QI = qiHandle.AddrOfPinnedObject(),
                    N_LENGTH = (ulong)output.N.LongLength,
                    E_LENGTH = (ulong)output.E.LongLength,
                    D_LENGTH = (ulong)output.D.LongLength,
                    P_LENGTH = (ulong)output.P.LongLength,
                    Q_LENGTH = (ulong)output.Q.LongLength,
                    DP_LENGTH = (ulong)output.DP.LongLength,
                    DQ_LENGTH = (ulong)output.DQ.LongLength,
                    QI_LENGTH = (ulong)output.QI.LongLength,
                };

                int result = RsaIOInterop.RsaGenerateParameters(ref paramters);
                if (result != 0)
                    throw new Exception("Error Get Paramters.");
                return output;
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
        }

        public void GenerateKeys(ulong size, ASYMMETRIC_KEY_FORMAT format, ref byte[] publicKey, ref byte[] privateKey, byte[] pemPassword = null, SYMMETRY_CRYPTER crypter = SYMMETRY_CRYPTER.SYMMETRY_AES_CBC, int cryptsize = 256, SEGMENT_SIZE_OPTION segment = SEGMENT_SIZE_OPTION.SEGMENT_128_BIT)
        {
            publicKey = new byte[size];
            privateKey = new byte[size];

            GCHandle publicKeyHandle = GCHandle.Alloc(publicKey, GCHandleType.Pinned);
            GCHandle privateKeyHandle = GCHandle.Alloc(privateKey, GCHandleType.Pinned);
            GCHandle pemPasswordHandle = GCHandle.Alloc(pemPassword, GCHandleType.Pinned);

            try
            {
                RSA_KEY_PAIR keypair = new RSA_KEY_PAIR
                {
                    KEY_LENGTH = size,
                    KEY_FORMAT = format,
                    PUBLIC_KEY = publicKeyHandle.AddrOfPinnedObject(),
                    PRIVATE_KEY = privateKeyHandle.AddrOfPinnedObject(),
                    PEM_PASSWORD = pemPasswordHandle.AddrOfPinnedObject(),
                    PUBLIC_KEY_LENGTH = (ulong)publicKey.LongLength,
                    PRIVATE_KEY_LENGTH = (ulong)privateKey.LongLength,
                    PEM_PASSWORD_LENGTH = pemPassword == null ? 0 : (ulong)pemPassword.LongLength,
                    PEM_CIPHER = crypter,
                    PEM_CIPHER_SIZE = cryptsize,
                    PEM_CIPHER_SEGMENT = segment,
                };

                int result = RsaIOInterop.RsaGenerateKeys(ref keypair);
                if (result != 0)
                {
                    publicKey = new byte[0];
                    privateKey = new byte[0];
                }
                else
                {
                    publicKey = publicKey.Take((int)keypair.PUBLIC_KEY_LENGTH).ToArray();
                    privateKey = privateKey.Take((int)keypair.PRIVATE_KEY_LENGTH).ToArray();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                if (publicKeyHandle.IsAllocated) publicKeyHandle.Free();
                if (privateKeyHandle.IsAllocated) privateKeyHandle.Free();
            }
        }

        public void GenerateCSR(
            ulong size,
            ASYMMETRIC_KEY_FORMAT format,
            ref byte[] csr,
            ref byte[] privateKey,
            RsaDistinguishedName distinguishedName = null,
            RsaSubjectAlternativeName subjectAlternativeName = null,
            ASYMMETRIC_KEY_CSR_KEY_USAGE keyUsage = ASYMMETRIC_KEY_CSR_KEY_USAGE.CSR_KEY_USAGE_NULL,
            HASH_TYPE hashAlgorithm = HASH_TYPE.HASH_SHA2_256,
            byte[] pemPassword = null,
            SYMMETRY_CRYPTER crypter = SYMMETRY_CRYPTER.SYMMETRY_AES_CBC,
            int cryptsize = 256,
            SEGMENT_SIZE_OPTION segment = SEGMENT_SIZE_OPTION.SEGMENT_128_BIT)
        {
            string sanString = subjectAlternativeName.Converter();

            csr = new byte[size];
            privateKey = new byte[size];
            byte[] commonNameBytes = distinguishedName.CommonName == null ? null : Encoding.UTF8.GetBytes(distinguishedName.CommonName).Concat(new byte[] { 0 }).ToArray();
            byte[] countryBytes = distinguishedName.Country == null ? null : Encoding.UTF8.GetBytes(distinguishedName.Country).Concat(new byte[] { 0 }).ToArray();
            byte[] organizationBytes = distinguishedName.Organization == null ? null : Encoding.UTF8.GetBytes(distinguishedName.Organization).Concat(new byte[] { 0 }).ToArray();
            byte[] organizationUnitBytes = distinguishedName.OrganizationalUnit == null ? null : Encoding.UTF8.GetBytes(distinguishedName.OrganizationalUnit).Concat(new byte[] { 0 }).ToArray();
            byte[] subjectAlternativeNameBytes = subjectAlternativeName == null ? null : Encoding.UTF8.GetBytes(sanString).Concat(new byte[] { 0 }).ToArray();

            GCHandle csrHandle = GCHandle.Alloc(csr, GCHandleType.Pinned);
            GCHandle privateKeyHandle = GCHandle.Alloc(privateKey, GCHandleType.Pinned);
            GCHandle pemPasswordHandle = GCHandle.Alloc(pemPassword, GCHandleType.Pinned);
            GCHandle commonNameHandle = GCHandle.Alloc(commonNameBytes, GCHandleType.Pinned);
            GCHandle countryHandle = GCHandle.Alloc(countryBytes, GCHandleType.Pinned);
            GCHandle organizationHandle = GCHandle.Alloc(organizationBytes, GCHandleType.Pinned);
            GCHandle organizationUnitHandle = GCHandle.Alloc(organizationUnitBytes, GCHandleType.Pinned);
            GCHandle subjectAlternativeNameHandle = GCHandle.Alloc(subjectAlternativeNameBytes, GCHandleType.Pinned);

            try
            {
                RSA_CSR req = new RSA_CSR
                {
                    KEY_LENGTH = size,
                    KEY_FORMAT = format,
                    CSR = csrHandle.AddrOfPinnedObject(),
                    PRIVATE_KEY = privateKeyHandle.AddrOfPinnedObject(),
                    PEM_PASSWORD = pemPasswordHandle.AddrOfPinnedObject(),
                    CSR_LENGTH = (ulong)csr.LongLength,
                    PRIVATE_KEY_LENGTH = (ulong)privateKey.LongLength,
                    PEM_PASSWORD_LENGTH = pemPassword == null ? 0 : (ulong)pemPassword.LongLength,
                    PEM_CIPHER = crypter,
                    PEM_CIPHER_SIZE = cryptsize,
                    PEM_CIPHER_SEGMENT = segment,
                    HASH_ALGORITHM = hashAlgorithm,
                    COMMON_NAME = commonNameHandle.AddrOfPinnedObject(),
                    COUNTRY = countryHandle.AddrOfPinnedObject(),
                    ORGANIZATION = organizationHandle.AddrOfPinnedObject(),
                    ORGANIZATION_UNIT = organizationUnitHandle.AddrOfPinnedObject(),
                    SUBJECT_ALTERNATIVE_NAME = subjectAlternativeNameHandle.AddrOfPinnedObject(),
                    KEY_USAGE = keyUsage,
                };

                int result = RsaIOInterop.RsaGenerateCSR(ref req);
                if (result != 0)
                {
                    csr = new byte[0];
                    privateKey = new byte[0];
                }
                else
                {
                    csr = csr.Take((int)req.CSR_LENGTH).ToArray();
                    privateKey = privateKey.Take((int)req.PRIVATE_KEY_LENGTH).ToArray();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                if (csrHandle.IsAllocated) csrHandle.Free();
                if (privateKeyHandle.IsAllocated) privateKeyHandle.Free();
                if (pemPasswordHandle.IsAllocated) pemPasswordHandle.Free();
                if (commonNameHandle.IsAllocated) commonNameHandle.Free();
                if (countryHandle.IsAllocated) countryHandle.Free();
                if (organizationHandle.IsAllocated) organizationHandle.Free();
                if (organizationUnitHandle.IsAllocated) organizationUnitHandle.Free();
                if (subjectAlternativeNameHandle.IsAllocated) subjectAlternativeNameHandle.Free();
            }
        }

        public void GenerateCA(
            ulong size,
            ASYMMETRIC_KEY_FORMAT format,
            ref byte[] certificate,
            RsaDistinguishedName distinguishedName = null,
            ASYMMETRIC_KEY_CSR_KEY_USAGE keyUsage = ASYMMETRIC_KEY_CSR_KEY_USAGE.CSR_KEY_USAGE_NULL,
            HASH_TYPE hashAlgorithm = HASH_TYPE.HASH_SHA2_256,
            ulong validityDays = 365,
            long serialNumber = 0)
        {
            certificate = new byte[size];
            byte[] commonNameBytes = distinguishedName.CommonName == null ? null : Encoding.UTF8.GetBytes(distinguishedName.CommonName).Concat(new byte[] { 0 }).ToArray();
            byte[] countryBytes = distinguishedName.Country == null ? null : Encoding.UTF8.GetBytes(distinguishedName.Country).Concat(new byte[] { 0 }).ToArray();
            byte[] organizationBytes = distinguishedName.Organization == null ? null : Encoding.UTF8.GetBytes(distinguishedName.Organization).Concat(new byte[] { 0 }).ToArray();
            byte[] organizationUnitBytes = distinguishedName.OrganizationalUnit == null ? null : Encoding.UTF8.GetBytes(distinguishedName.OrganizationalUnit).Concat(new byte[] { 0 }).ToArray();

            GCHandle certificateHandle = GCHandle.Alloc(certificate, GCHandleType.Pinned);
            GCHandle commonNameHandle = GCHandle.Alloc(commonNameBytes, GCHandleType.Pinned);
            GCHandle countryHandle = GCHandle.Alloc(countryBytes, GCHandleType.Pinned);
            GCHandle organizationHandle = GCHandle.Alloc(organizationBytes, GCHandleType.Pinned);
            GCHandle organizationUnitHandle = GCHandle.Alloc(organizationUnitBytes, GCHandleType.Pinned);

            try
            {
                RSA_CA ca = new RSA_CA
                {
                    KEY_LENGTH = size,
                    KEY_FORMAT = format,
                    CERTIFICATE = certificateHandle.AddrOfPinnedObject(),
                    CERTIFICATE_LENGTH = (ulong)certificate.LongLength,
                    HASH_ALGORITHM = hashAlgorithm,
                    COMMON_NAME = commonNameHandle.AddrOfPinnedObject(),
                    COUNTRY = countryHandle.AddrOfPinnedObject(),
                    ORGANIZATION = organizationHandle.AddrOfPinnedObject(),
                    ORGANIZATION_UNIT = organizationUnitHandle.AddrOfPinnedObject(),
                    KEY_USAGE = keyUsage,
                    VALIDITY_DAYS = validityDays,
                    SERIAL_NUMBER = serialNumber,
                };

                int result = RsaIOInterop.RsaGenerateCA(ref ca);
                if (result != 0)
                {
                    certificate = new byte[0];
                }
                else
                {
                    certificate = certificate.Take((int)ca.CERTIFICATE_LENGTH).ToArray();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                if (certificateHandle.IsAllocated) certificateHandle.Free();
                if (commonNameHandle.IsAllocated) commonNameHandle.Free();
                if (countryHandle.IsAllocated) countryHandle.Free();
                if (organizationHandle.IsAllocated) organizationHandle.Free();
                if (organizationUnitHandle.IsAllocated) organizationUnitHandle.Free();
            }
        }

        public RsaParamters ToParamters(ASYMMETRIC_KEY_FORMAT format, byte[] publicKey, byte[] privateKey)
        {
            ulong size = this.GetKeyLength(format, publicKey, privateKey);
            if (size == 0)
                return null;
            RsaParamters output = this.CreateEmptyParamters(size);
            if (output == null)
                return output;

            GCHandle nHandle = GCHandle.Alloc(output.N, GCHandleType.Pinned);
            GCHandle eHandle = GCHandle.Alloc(output.E, GCHandleType.Pinned);
            GCHandle dHandle = GCHandle.Alloc(output.D, GCHandleType.Pinned);
            GCHandle pHandle = GCHandle.Alloc(output.P, GCHandleType.Pinned);
            GCHandle qHandle = GCHandle.Alloc(output.Q, GCHandleType.Pinned);
            GCHandle dpHandle = GCHandle.Alloc(output.DP, GCHandleType.Pinned);
            GCHandle dqHandle = GCHandle.Alloc(output.DQ, GCHandleType.Pinned);
            GCHandle qiHandle = GCHandle.Alloc(output.QI, GCHandleType.Pinned);
            GCHandle publicKeyHandle = GCHandle.Alloc(publicKey, GCHandleType.Pinned);
            GCHandle privateKeyHandle = GCHandle.Alloc(privateKey, GCHandleType.Pinned);

            try
            {
                RSA_EXPORT paramters = new RSA_EXPORT
                {
                    KEY_LENGTH = size,
                    KEY_FORMAT = format,
                    N = nHandle.AddrOfPinnedObject(),
                    E = eHandle.AddrOfPinnedObject(),
                    D = dHandle.AddrOfPinnedObject(),
                    P = pHandle.AddrOfPinnedObject(),
                    Q = qHandle.AddrOfPinnedObject(),
                    DP = dpHandle.AddrOfPinnedObject(),
                    DQ = dqHandle.AddrOfPinnedObject(),
                    QI = qiHandle.AddrOfPinnedObject(),
                    N_LENGTH = (ulong)output.N.LongLength,
                    E_LENGTH = (ulong)output.E.LongLength,
                    D_LENGTH = (ulong)output.D.LongLength,
                    P_LENGTH = (ulong)output.P.LongLength,
                    Q_LENGTH = (ulong)output.Q.LongLength,
                    DP_LENGTH = (ulong)output.DP.LongLength,
                    DQ_LENGTH = (ulong)output.DQ.LongLength,
                    QI_LENGTH = (ulong)output.QI.LongLength,
                    PUBLIC_KEY = publicKeyHandle.AddrOfPinnedObject(),
                    PRIVATE_KEY = privateKeyHandle.AddrOfPinnedObject(),
                    PUBLIC_KEY_LENGTH = (ulong)publicKey.LongLength,
                    PRIVATE_KEY_LENGTH = (ulong)privateKey.LongLength,
                };
                int result = RsaIOInterop.RsaExportParameters(ref paramters);
                if (result != 0)
                    throw new Exception("Error To Rsa Key To Paramters.");
                return output;
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
                if (publicKeyHandle.IsAllocated) publicKeyHandle.Free();
                if (privateKeyHandle.IsAllocated) privateKeyHandle.Free();
            }
        }

        public void ToKeys(RsaParamters paramters, ASYMMETRIC_KEY_FORMAT format, ref byte[] publicKey, ref byte[] privateKey)
        {
            ulong size = (ulong)paramters.N.LongLength * 8;
            publicKey = new byte[size];
            privateKey = new byte[size];
            GCHandle nHandle = GCHandle.Alloc(paramters.N, GCHandleType.Pinned);
            GCHandle eHandle = GCHandle.Alloc(paramters.E, GCHandleType.Pinned);
            GCHandle dHandle = GCHandle.Alloc(paramters.D, GCHandleType.Pinned);
            GCHandle pHandle = GCHandle.Alloc(paramters.P, GCHandleType.Pinned);
            GCHandle qHandle = GCHandle.Alloc(paramters.Q, GCHandleType.Pinned);
            GCHandle dpHandle = GCHandle.Alloc(paramters.DP, GCHandleType.Pinned);
            GCHandle dqHandle = GCHandle.Alloc(paramters.DQ, GCHandleType.Pinned);
            GCHandle qiHandle = GCHandle.Alloc(paramters.QI, GCHandleType.Pinned);
            GCHandle publicKeyHandle = GCHandle.Alloc(publicKey, GCHandleType.Pinned);
            GCHandle privateKeyHandle = GCHandle.Alloc(privateKey, GCHandleType.Pinned);

            try
            {
                RSA_EXPORT keypair = new RSA_EXPORT
                {
                    KEY_LENGTH = size,
                    KEY_FORMAT = format,
                    N = nHandle.AddrOfPinnedObject(),
                    E = eHandle.AddrOfPinnedObject(),
                    D = dHandle.AddrOfPinnedObject(),
                    P = pHandle.AddrOfPinnedObject(),
                    Q = qHandle.AddrOfPinnedObject(),
                    DP = dpHandle.AddrOfPinnedObject(),
                    DQ = dqHandle.AddrOfPinnedObject(),
                    QI = qiHandle.AddrOfPinnedObject(),
                    N_LENGTH = (ulong)paramters.N.LongLength,
                    E_LENGTH = (ulong)paramters.E.LongLength,
                    D_LENGTH = (ulong)paramters.D.LongLength,
                    P_LENGTH = (ulong)paramters.P.LongLength,
                    Q_LENGTH = (ulong)paramters.Q.LongLength,
                    DP_LENGTH = (ulong)paramters.DP.LongLength,
                    DQ_LENGTH = (ulong)paramters.DQ.LongLength,
                    QI_LENGTH = (ulong)paramters.QI.LongLength,
                    PUBLIC_KEY = publicKeyHandle.AddrOfPinnedObject(),
                    PRIVATE_KEY = privateKeyHandle.AddrOfPinnedObject(),
                    PUBLIC_KEY_LENGTH = (ulong)publicKey.LongLength,
                    PRIVATE_KEY_LENGTH = (ulong)privateKey.LongLength,
                };
                int result = RsaIOInterop.RsaExportKeys(ref keypair);
                if (result != 0)
                {
                    publicKey = new byte[0];
                    privateKey = new byte[0];
                }
                else
                {
                    publicKey = publicKey.Take((int)keypair.PUBLIC_KEY_LENGTH).ToArray();
                    privateKey = privateKey.Take((int)keypair.PRIVATE_KEY_LENGTH).ToArray();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
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
                if (publicKeyHandle.IsAllocated) publicKeyHandle.Free();
                if (privateKeyHandle.IsAllocated) privateKeyHandle.Free();
            }
        }

        public void ExtractPublicKey(ASYMMETRIC_KEY_FORMAT publicKeyFormat, ASYMMETRIC_KEY_FORMAT privateKeyFormat, ref byte[] publicKey, byte[] privateKey, byte[] pemPassword = null)
        {
            ulong size = this.GetKeyLength(privateKeyFormat, publicKey, privateKey, pemPassword);
            if (size == 0)
                throw new Exception("Error Get Key Length.");

            publicKey = new byte[size];

            GCHandle publicKeyHandle = GCHandle.Alloc(publicKey, GCHandleType.Pinned);
            GCHandle privateKeyHandle = GCHandle.Alloc(privateKey, GCHandleType.Pinned);
            GCHandle pemPasswordHandle = GCHandle.Alloc(pemPassword, GCHandleType.Pinned);

            try
            {
                RSA_EXTRACT_PUBLIC_KEY extract = new RSA_EXTRACT_PUBLIC_KEY
                {
                    PUBLIC_KEY_FORMAT = publicKeyFormat,
                    PRIVATE_KEY_FORMAT = privateKeyFormat,
                    PUBLIC_KEY = publicKeyHandle.AddrOfPinnedObject(),
                    PRIVATE_KEY = privateKeyHandle.AddrOfPinnedObject(),
                    PEM_PASSWORD = pemPasswordHandle.AddrOfPinnedObject(),
                    PUBLIC_KEY_LENGTH = (ulong)publicKey.LongLength,
                    PRIVATE_KEY_LENGTH = (ulong)privateKey.LongLength,
                    PEM_PASSWORD_LENGTH = pemPassword == null ? 0 : (ulong)pemPassword.LongLength,
                };

                int result = RsaIOInterop.RsaExtractPublicKey(ref extract);
                if (result != 0)
                    throw new Exception("Error Extract Rsa Publlic Key.");

                publicKey = publicKey.Take((int)extract.PUBLIC_KEY_LENGTH).ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                if (publicKeyHandle.IsAllocated) publicKeyHandle.Free();
                if (privateKeyHandle.IsAllocated) privateKeyHandle.Free();
                if (pemPasswordHandle.IsAllocated) pemPasswordHandle.Free();
            }
        }
    }
}
