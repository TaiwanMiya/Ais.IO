using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public class RsaParamters
    {
        public byte[] N { get; set; }
        public byte[] E { get; set; }
        public byte[] D { get; set; }
        public byte[] P { get; set; }
        public byte[] Q { get; set; }
        public byte[] DP { get; set; }
        public byte[] DQ { get; set; }
        public byte[] QI { get; set; }
    }

    public class  RsaDistinguishedName
    {
        public string CommonName { get; set; }
        public string Country { get; set; }
        public string Organization { get; set; }
        public string OrganizationalUnit { get; set; }
    }

    public class RsaSubjectAlternativeName
    {
        [DisplayName("DNS:")]
        public string DNS { get; set; }

        [DisplayName("IP:")]
        public string IP { get; set; }

        [DisplayName("email:")]
        public string Email { get; set; }

        [DisplayName("URI:")]
        public string URI { get; set; }

        internal string Converter()
        {
            StringBuilder dns = new StringBuilder(this.DNS);
            StringBuilder ip = new StringBuilder(this.IP);
            StringBuilder email = new StringBuilder(this.Email);
            StringBuilder uri = new StringBuilder(this.URI);

            bool dns_success = CheckValidInterop.IsValidDNS(dns);
            bool ip_success = CheckValidInterop.IsValidIPv4(ip);
            if (!ip_success)
                ip_success = CheckValidInterop.IsValidIPv6(ip);
            bool email_success = CheckValidInterop.IsValidEmail(email);
            bool uri_success = CheckValidInterop.IsValidURI(uri);

            if (!dns_success)
                throw new ArgumentException("No valid Subject Alternative Name By DNS.");
            if (!ip_success)
                throw new ArgumentException("No valid Subject Alternative Name By IP.");
            if (!email_success)
                throw new ArgumentException("No valid Subject Alternative Name By Email.");
            if (!uri_success)
                throw new ArgumentException("No valid Subject Alternative Name By URI.");

            var type = typeof(RsaSubjectAlternativeName);
            string value = string.Empty;

            foreach (PropertyInfo prop in type.GetProperties())
            {
                DisplayNameAttribute displayNameAttr = (DisplayNameAttribute)Attribute.GetCustomAttribute(prop, typeof(DisplayNameAttribute));

                string displayName = displayNameAttr != null
                    ? displayNameAttr.DisplayName
                    : null;

                value += displayName == null ? string.Empty : displayName + prop.GetValue(this, null).ToString() + ",";
            }
            if (value.EndsWith(","))
                value = value.TrimEnd(',');

            if (string.IsNullOrEmpty(value))
                return null;
            return value;
        }
    }
}
