using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Security.Cryptography.X509Certificates;

namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Methods to help with certificate parsing
    /// </summary>
    public static class CertificateHelper
    {
        /// <summary>
        /// Parse the certificate subject and generate a DodUser
        /// </summary>
        /// <param name="subject">The subject of a certificate</param>
        /// <returns>A DodUser</returns>
        public static DodUser ExtractDodUser(string subject)
        {
            var user = new DodUser();
            var subjectSections = subject.Split(',');

            foreach(var section in subjectSections)
            {
                var trimmed = section.Trim();

                if(trimmed.StartsWith("CN"))
                {
                    var segments = trimmed.Substring(3, trimmed.Length - 3).Split('.');
                    for(int i = segments.Length - 1; i >= 0; i--)
                    {
                        if(string.IsNullOrEmpty(user.DodId))
                        {
                            long dodId;
                            if(segments[i].Length != 10 || !Int64.TryParse(segments[i], out dodId))
                                throw new InvalidOperationException(string.Format("The Edipi value {0} is not valid", segments[i]));
                            else
                                user.DodId = segments[i];
                        }
                        else if(string.IsNullOrEmpty(user.MiddleName))
                            user.MiddleName = segments[i];
                        else if(string.IsNullOrEmpty(user.FirstName))
                            user.FirstName = segments[i];
                        else if(string.IsNullOrEmpty(user.LastName))
                            user.LastName = segments[i];
                        else user.MiddleName += "." + segments[i];
                    }

                    break;
                }
            }

            return user;
        }
    }
}
