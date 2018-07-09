using Microsoft.VisualStudio.TestTools.UnitTesting;
using Psns.Common.Security.ClientCertificateHandling;
using System;
using static Psns.Common.Functional.Prelude;
using static Psns.Common.Security.ClientCertificateHandling.DodUserExtentions;

namespace ClientCertificateHandling.UnitTests
{
    [TestClass]
    public class WhenWorkingWithTheDodUser
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DodIdIsNull_ExceptionThrown()
        {
            var user = new DodUser(null, None, None, None, None);

            Assert.Fail();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DodIdIsNull_FromExtension_ExceptionThrown()
        {
            var user = FromDodId(null);

            Assert.Fail();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DodIdIsEmpty_ExceptionThrown()
        {
            var user = new DodUser(string.Empty, None, None, None, None);
            Assert.Fail();
        }
    }
}