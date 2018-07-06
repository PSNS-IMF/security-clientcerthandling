using Microsoft.VisualStudio.TestTools.UnitTesting;
using Psns.Common.Security.ClientCertificateHandling;
using System;
using System.Collections.Specialized;
using System.Security.Cryptography.X509Certificates;
using static Psns.Common.Functional.Prelude;

namespace ClientCertificateHandling.UnitTests
{
    [TestClass]
    public class WhenWorkingWithTheBigIPHeaderCertParser
    {
        [TestMethod]
        public void ParsingAValidCert()
        {
            var user = new X509Certificate2(Properties.Resources.testcert).ExtractDodUser();

            Assert.AreEqual("1234567890", user.DodId);
            Assert.AreEqual("firstname", user.FirstName);
            Assert.AreEqual("lastname", user.LastName);
            Assert.AreEqual("middle", user.MiddleName);
        }

        [TestMethod]
        public void ParsingAValidCertBinaryString()
        {
            var headers = new NameValueCollection();
            var certBinaryString = Convert.ToBase64String(Properties.Resources.testcert);
            headers.Add(Constants.F5CertificateBinaryHeaderValueName, certBinaryString);

            var user = certBinaryString.ExtractDodUser(
                headers, 
                CrlCheckMode.Offline, 
                Cons(X509ChainStatusFlags.UntrustedRoot));

            Assert.AreEqual("1234567890", user.DodId);
            Assert.AreEqual("firstname", user.FirstName);
            Assert.AreEqual("lastname", user.LastName);
            Assert.AreEqual("middle", user.MiddleName);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidCertificateException))]
        public void ParsingInvalidCert()
        {
            var headers = new NameValueCollection();
            var certBinaryString = Convert.ToBase64String(Properties.Resources.testcert);
            headers.Add(Constants.F5CertificateBinaryHeaderValueName, certBinaryString);

            var user = Convert.ToBase64String(new byte[] { 1, 2, 3 }).ExtractDodUser(headers, CrlCheckMode.Offline, Empty<X509ChainStatusFlags>());
            Assert.Fail();
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidCertificateException))]
        public void ParsingUnvalidatableCert()
        {
            var headers = new NameValueCollection();
            var certBinaryString = Convert.ToBase64String(Properties.Resources.testcert);
            headers.Add(Constants.F5CertificateBinaryHeaderValueName, certBinaryString);

            var user = Convert.ToBase64String(new byte[0]).ExtractDodUser(headers, CrlCheckMode.Offline, Empty<X509ChainStatusFlags>());
            Assert.Fail();
        }
    }
}