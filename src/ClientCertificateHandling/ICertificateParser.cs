using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Represents an object that parses the client certificate provided
    /// by the BigIP and constructs a DodUser from its values
    /// </summary>
    public interface ICertificateParser
    {
        /// <summary>
        /// Parse the client cert and construct a DodUser
        /// </summary>
        /// <returns>A DodUser</returns>
        DodUser Parse();

        /// <summary>
        /// Parse the client cert and construct a DodUser
        /// </summary>
        /// <param name="crlCheckMode">Whether to check the Crl online (slow) or use the local cache offline</param>
        /// <returns>A DodUser</returns>
        DodUser Parse(CrlCheckMode crlCheckMode);
    }
}
