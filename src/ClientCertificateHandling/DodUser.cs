using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Basic properties of every DodUser
    /// </summary>
    public class DodUser
    {
        /// <summary>
        /// The DodId/EDIPI
        /// </summary>
        public int DodId { get; set; }

        public string FirstName { get; set; }
        public string MiddleName { get; set; }
        public string LastName { get; set; }
    }
}
