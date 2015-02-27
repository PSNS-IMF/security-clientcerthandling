using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Psns.Common.Security.ClientCertificateHandling;
using Psns.Common.Test.BehaviorDrivenDevelopment;
using Psns.Common.Web.Adapters;

using Moq;

namespace ClientCertificateHandling.UnitTests
{
    public class WhenWorkingWithTheLocalCertificateParser : BehaviorDrivenDevelopmentCaseTemplate
    {
        protected RequestCertificateParser Parser;
        protected DodUser User;

        public override void Arrange()
        {
            base.Arrange();

            Parser = new RequestCertificateParser();
        }

        public override void Act()
        {
            base.Act();

            User = Parser.Parse(CrlCheckMode.Offline);
        }
    }

    [TestClass]
    public class AndCertificateIsValid : WhenWorkingWithTheLocalCertificateParser
    {
        public override void Arrange()
        {
            base.Arrange();

            HttpClientCertificateAdapter.Subject = "CN=user.test.middle.1234567890";
        }

        [TestMethod]
        public void TheTheCorrectDodUserShouldBeReturned()
        {
            Assert.AreEqual<int>(1234567890, User.DodId);
            Assert.AreEqual<string>("test", User.FirstName);
            Assert.AreEqual<string>("user", User.LastName);
            Assert.AreEqual<string>("middle", User.MiddleName);
        }
    }

    [TestClass]
    public class AndCertificateIsValidAltToken : WhenWorkingWithTheLocalCertificateParser
    {
        public override void Arrange()
        {
            base.Arrange();

            HttpClientCertificateAdapter.Subject = "CN=alt.user.test.middle.1234567890";
        }

        [TestMethod]
        public void TheTheCorrectDodUserShouldBeReturned()
        {
            Assert.AreEqual<int>(1234567890, User.DodId);
            Assert.AreEqual<string>("test", User.FirstName);
            Assert.AreEqual<string>("user", User.LastName);
            Assert.AreEqual<string>("middle.alt", User.MiddleName);
        }
    }

    [TestClass]
    public class AndCertificateSubjectIsEmpty : WhenWorkingWithTheLocalCertificateParser
    {
        public override void Arrange()
        {
            base.Arrange();

            HttpClientCertificateAdapter.Subject = string.Empty;
        }

        public override void Act()
        {

        }

        [TestMethod]
        [ExpectedException(typeof(InvalidCertificateException))]
        public void ThenAnInvalidCertificateExceptionShouldBeThrown()
        {
            User = Parser.Parse(CrlCheckMode.Offline);
            Assert.Fail();
        }
    }
}