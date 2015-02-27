using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Web;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Psns.Common.Web.Adapters;

namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Provide modes for Crl checking
    /// </summary>
    public enum CrlCheckMode
    {
        /// <summary>
        /// Check revocation status with online CRL (takes longer)
        /// </summary>
        Online = 1,
        /// <summary>
        /// Check revocation status with cached CRL
        /// </summary>
        Offline = 2
    }

    /// <summary>
    /// Parses the client certificate from the BipIP inserted iRole http header value "ssl.client_cert"
    /// </summary>
    public class BigIPHeaderCertificateParser : ICertificateParser
    {
        /// <summary>
        /// Try to parse the client certificate
        /// </summary>
        /// <returns>A DodUser</returns>
        public DodUser Parse()
        {
            return Parse(CrlCheckMode.Online);
        }

        /// <summary>
        /// Parses the client certificate from the current HttpRequest header
        /// </summary>
        /// <param name="crlCheckMode">Set whether CRL check will use local cache or go online</param>
        /// <returns>A DodUser object</returns>
        /// <exception cref="Psns.Common.Security.ClientCertificateHandling.InvalidCertificateException"></exception>
        public DodUser Parse(CrlCheckMode crlCheckMode)
        {
            X509Certificate2 x509 = null;
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = (X509RevocationMode)
                Enum.Parse(typeof(X509RevocationMode), crlCheckMode.ToString());

            try
            {
                x509 = new X509Certificate2(Convert
                    .FromBase64String(HttpContextAdapter
                        .Current
                        .Request
                        .Headers["ssl.client_cert"]));

                chain.Build(x509);
            }
            catch(Exception e)
            {
                if(e is CryptographicException || e is ArgumentException)
                    throw new InvalidCertificateException("The certificate is unreadable", e);
                else
                    throw;
            }
            
            foreach(var status in chain.ChainStatus)
            {
                if(!ChainStatusWhiteListPolicy.Current.Contains(status.Status))
                    throw new InvalidCertificateException(status.StatusInformation);
            }

            return CertificateHelper.ExtractDodUser(x509.Subject);
        }
    }
}
