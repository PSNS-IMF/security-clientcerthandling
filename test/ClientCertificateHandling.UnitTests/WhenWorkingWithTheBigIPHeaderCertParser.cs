using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.IO;
using System.Web;
using System.Collections.Specialized;
using System.Security.Cryptography.X509Certificates;

using Psns.Common.Security.ClientCertificateHandling;
using Psns.Common.Test.BehaviorDrivenDevelopment;
using Psns.Common.Web.Adapters;

using Moq;

namespace ClientCertificateHandling.UnitTests
{
    public class WhenWorkingWithTheBigIPHeaderCertParser : BehaviorDrivenDevelopmentCaseTemplate
    {
        protected BigIPHeaderCertificateParser Parser;
        protected DodUser User;

        public override void Arrange()
        {
            base.Arrange();

            var mockContext = new Mock<HttpContextBase>();
            var mockRequest = new Mock<HttpRequestBase>();
            var mockResponse = new Mock<HttpResponseBase>();

            mockRequest.Setup(r => r.Url).Returns(new Uri("http://test.com"));
            mockRequest.SetupGet(r => r.Headers).Returns(new NameValueCollection());

            mockContext.Setup(c => c.Request).Returns(mockRequest.Object);
            mockContext.Setup(c => c.Response).Returns(mockResponse.Object);

            HttpContextAdapter.Current = mockContext.Object;

            Parser = new BigIPHeaderCertificateParser();
        }

        public override void Act()
        {
            base.Act();

            User = Parser.Parse(CrlCheckMode.Offline);
        }
    }

    [TestClass]
    public class AndParsingAValidCert : WhenWorkingWithTheBigIPHeaderCertParser
    {
        public override void Arrange()
        {
            base.Arrange();

            ChainStatusWhiteListPolicy.Add(X509ChainStatusFlags.UntrustedRoot);

            HttpContextAdapter.Current.Request.Headers.Add("ssl.client_cert", 
                Convert.ToBase64String(ClientCertificateHandling.UnitTests.Properties.Resources.testcert));
        }

        [TestMethod]
        public void ThenTheCorrectUserShouldBeReturned()
        {
            Assert.AreEqual<int>(1234567890, User.DodId);
            Assert.AreEqual<string>("firstname", User.FirstName);
            Assert.AreEqual<string>("lastname", User.LastName);
            Assert.AreEqual<string>("middle", User.MiddleName);
        }
    }

    [TestClass]
    public class AndParsingAnInvalidCert : WhenWorkingWithTheBigIPHeaderCertParser
    {
        public override void Arrange()
        {
            base.Arrange();

            HttpContextAdapter.Current.Request.Headers.Add("ssl.client_cert",
                Convert.ToBase64String(new byte[] { 0, 1, 2 }));
        }

        public override void Act()
        {
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidCertificateException))]
        public void ThenAnInvalidCertificateExceptionShouldBeThrown()
        {
            User = Parser.Parse();
            Assert.Fail();
        }
    }

    [TestClass]
    public class AndParsingANonVerifiableCert : WhenWorkingWithTheBigIPHeaderCertParser
    {
        public override void Arrange()
        {
            base.Arrange();

            HttpContextAdapter.Current.Request.Headers.Add("ssl.client_cert",
                Convert.ToBase64String(new byte[0]));
        }

        public override void Act()
        {
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidCertificateException))]
        public void ThenAnInvalidCertificateExceptionShouldBeThrown()
        {
            User = Parser.Parse();
            Assert.Fail();
        }
    }
}