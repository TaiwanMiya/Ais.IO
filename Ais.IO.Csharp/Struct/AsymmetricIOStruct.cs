using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public enum ASYMMETRIC_KEY_FORMAT
    {
        ASYMMETRIC_KEY_PEM = 0,
        ASYMMETRIC_KEY_DER = 1,
    };

    public enum ASYMMETRIC_KEY_CSR_KEY_USAGE
    {
        CSR_KEY_USAGE_NULL              = 0x0000,
        CSR_KEY_USAGE_DIGITAL_SIGNATURE = 0x0001,
        CSR_KEY_USAGE_KEY_ENCIPHERMENT  = 0x0002,
        CSR_KEY_USAGE_DATA_ENCIPHERMENT = 0x0004,
        CSR_KEY_USAGE_KEY_AGREEMENT     = 0x0008,
        CSR_KEY_USAGE_CERT_SIGN         = 0x0010,
        CSR_KEY_USAGE_CRL_SIGN          = 0x0020,
    }
}
