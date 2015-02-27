using System;
using System.Collections.Generic;
using System.Linq;

using Psns.Common.Web.Adapters;

namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Used to parse the client certificate from HttpRequest.ClientCertificate
    /// </summary>
    public class RequestCertificateParser : ICertificateParser
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
        /// Try to parse the certificate
        /// </summary>
        /// <param name="crlCheckMode"></param>
        /// <returns>A DodUser</returns>
        public DodUser Parse(CrlCheckMode crlCheckMode)
        {
            var subject = HttpClientCertificateAdapter.Subject;
            if(string.IsNullOrEmpty(subject))
                throw new InvalidCertificateException("Client certificate or Subject is missing");

            return CertificateHelper.ExtractDodUser(subject);
        }
    }
}