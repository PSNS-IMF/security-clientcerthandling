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
        /// Key Usage OID for Server
        /// </summary>
        public const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

        /// <summary>
        /// Key Usage OID for Client
        /// </summary>
        public const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

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
                                user = user.WithDodId(segments[i]);
                        }
                        else if (user.MiddleName.IsNone)
                            user = user.WithMiddleName(segments[i]);
                        else if (user.FirstName.IsNone)
                            user = user.WithFirstName(segments[i]);
                        else if (user.LastName.IsNone)
                            user = user.WithLastName(segments[i]);
                        else user = user.WithMiddleName(
                            user.MiddleName.Match(mn => mn, () => string.Empty) + "." + segments[i]);
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
            self
                .Subject
                .FromSubject()
                .WithEmail(
                    Try(() => self.GetNameInfo(X509NameType.EmailName, false))
                        .Match(
                            success: email => email,
                            fail: ex => string.Empty));

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

        /// <summary>
        /// Determines if <paramref name="self"/> is intended for Server Authentication.
        /// </summary>
        /// <param name="self"></param>
        /// <returns></returns>
        public static bool IsForServerAuthentication(this X509Certificate2 self) =>
            self.IsForUsage(ServerAuthenticationOid);

        /// <summary>
        /// Determines if <paramref name="self"/> is intended for Client Authentication.
        /// </summary>
        /// <param name="self"></param>
        /// <returns></returns>
        public static bool IsForClientAuthentication(this X509Certificate2 self) =>
            self.IsForUsage(ClientAuthenticationOid);

        /// <summary>
        /// Determines if <paramref name="self"/> is intended for all of the <paramref name="oids"/> usages.
        /// </summary>
        /// <param name="self"></param>
        /// <param name="oids"></param>
        /// <returns></returns>
        public static bool IsForUsage(this X509Certificate2 self, params string[] oids)
        {
            foreach (var extension in self.Extensions)
            {
                if (extension is X509EnhancedKeyUsageExtension enhanced)
                {
                    if (oids.All(oid => enhanced.EnhancedKeyUsages[oid] != null))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Extracts a user name from a <see cref="X509Certificate2"/>'s Subject.
        /// </summary>
        /// <param name="self"></param>
        /// <returns></returns>
        public static string UserName(this X509Certificate2 self) =>
            self
                ?.Subject
                ?.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                ?.Map(sections =>
                    sections[0].Map(cn =>
                        cn.Length > 3
                            ? cn.Substring(3, cn.Length - 3)
                            : string.Empty));

        /// <summary>
        /// Searches for a certificate in <paramref name="location"/> by <see cref="X509FindType.FindByKeyUsage" /> with
        /// usage <see cref="X509KeyUsageFlags.DigitalSignature" /> that also has EnhancedUsages as specified by
        /// <paramref name="oids"/>.
        /// </summary>
        /// <param name="location"></param>
        /// <param name="name"></param>
        /// <param name="oids"></param>
        /// <returns></returns>
        public static Either<Exception, X509Certificate2> FindSignatureCertificateByUsage(
            StoreLocation location = StoreLocation.LocalMachine,
            StoreName name = StoreName.My,
            params string[] oids)
        {
            var store = new X509Store(name, location);

            var result = Try(() => { store.Open(OpenFlags.ReadOnly); return store; })
                .Bind(_ =>
                    store.Certificates.Find(
                        X509FindType.FindByKeyUsage,
                        X509KeyUsageFlags.DigitalSignature,
                        true))
                .Bind(certs =>
                {
                    if (certs.Count > 0)
                    {
                        foreach (var cert in certs)
                        {
                            if (cert.IsForUsage(oids))
                            {
                                return cert.ToTry();
                            }
                        }
                    }

                    return FailWith<X509Certificate2>("No valid certificate found");
                }).ToEither();
    
#if (NETSTANDARD1_6)
            store.Dispose();
#else
            store.Close();
#endif

            return result;
        }

        /// <summary>
        /// Builds a <see cref="X509Chain" /> to determine if <paramref name="cert"/> is valid
        /// according to <paramref name="chainPolicy"/>.
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="chainPolicy"></param>
        /// <returns></returns>
        public static Either<Exception, (bool isValid, X509ChainStatus[] chainStatus)> Validate(this X509Certificate2 cert, X509ChainPolicy chainPolicy)
        {
#if (NETSTANDARD1_6)
            using (var chain = new X509Chain())
            {
#else
                var chain = new X509Chain();
#endif
                chain.ChainPolicy = chainPolicy;

                try
                {
                    var isValid = chain.Build(cert);

                    return (isValid, chain.ChainStatus);
                }
                catch (Exception e)
                {
                    return e;
                }
#if (NETSTANDARD1_6)
            }
#endif
        }

        static R Map<T, R>(this T t, Func<T, R> mapper) =>
            mapper(t);
    }
}
