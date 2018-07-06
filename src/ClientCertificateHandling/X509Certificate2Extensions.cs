using Psns.Common.Functional;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static Psns.Common.Functional.Prelude;

namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Methods to help with certificate parsing
    /// </summary>
    public static class X509Certificate2Extensions
    {
        /// <summary>
        /// Assumes <paramref name="self"/> is the subject of a <see cref="X509Certificate2"/>.
        /// </summary>
        /// <param name="self"></param>
        /// <returns></returns>
        public static DodUser FromSubject(this string self)
        {
            var user = new DodUser();
            var subjectSections = self.Split(',');

            foreach (var section in subjectSections)
            {
                var trimmed = section.Trim();

                if (trimmed.StartsWith("CN"))
                {
                    var segments = trimmed.Substring(3, trimmed.Length - 3).Split('.');
                    for (int i = segments.Length - 1; i >= 0; i--)
                    {
                        if (string.IsNullOrEmpty(user.DodId))
                        {
                            long dodId;
                            if (segments[i].Length != 10 || !Int64.TryParse(segments[i], out dodId))
                                throw new InvalidOperationException(string.Format("The Edipi value {0} is not valid", segments[i]));
                            else
                                user.DodId = segments[i];
                        }
                        else if (string.IsNullOrEmpty(user.MiddleName))
                            user.MiddleName = segments[i];
                        else if (string.IsNullOrEmpty(user.FirstName))
                            user.FirstName = segments[i];
                        else if (string.IsNullOrEmpty(user.LastName))
                            user.LastName = segments[i];
                        else user.MiddleName += "." + segments[i];
                    }

                    break;
                }
            }

            return user;
        }

        /// <summary>
        /// Parse the certificate subject and generate a DodUser
        /// </summary>
        /// <param name="self"></param>
        /// <returns>A DodUser</returns>
        public static DodUser ExtractDodUser(this X509Certificate2 self) =>
            self.Subject.FromSubject();

        /// <summary>
        /// Assumes that <paramref name="self"/> is the base 64 string encoded binary of a <see cref="X509Certificate2"/>.
        /// </summary>
        /// <param name="self"></param>
        /// <param name="headerValues">A collection of header values containing <see cref="Constants.F5CertificateBinaryHeaderValueName"/></param>
        /// <param name="crlCheckMode"></param>
        /// <param name="ignoreFlags">Chain status flags to be ignored when validating the <see cref="X509Chain"/></param>
        /// <returns></returns>
        /// <remarks><see cref="X509ChainStatusFlags.NoError"/> will always be ignore when validating the <see cref="X509Chain"/>.</remarks>
        public static DodUser ExtractDodUser(
            this string self, 
            NameValueCollection headerValues, 
            CrlCheckMode crlCheckMode,
            IEnumerable<X509ChainStatusFlags> ignoreFlags)
        {
            X509Certificate2 x509 = null;
            var chain = new X509Chain();

            chain.ChainPolicy.RevocationMode = (X509RevocationMode)
                Enum.Parse(typeof(X509RevocationMode), crlCheckMode.ToString());

            ignoreFlags = X509ChainStatusFlags.NoError.Cons(ignoreFlags);

            try
            {
                x509 = new X509Certificate2(Convert
                    .FromBase64String(headerValues[Constants.F5CertificateBinaryHeaderValueName]));

                chain.Build(x509);
            }
            catch (Exception e)
            {
                if (e is CryptographicException || e is ArgumentException)
                    throw new InvalidCertificateException("The certificate is unreadable", e);
                else
                    throw;
            }

            foreach (var status in chain.ChainStatus)
            {
                if (!ignoreFlags.Contains(status.Status))
                    throw new InvalidCertificateException(status.StatusInformation);
            }

            return x509.ExtractDodUser();
        }
    }
}
