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
        public string DodId { get; set; }

        /// <summary>
        /// First Name
        /// </summary>
        public string FirstName { get; set; }

        /// <summary>
        /// Middle Name
        /// </summary>
        public string MiddleName { get; set; }

        /// <summary>
        /// Last Name
        /// </summary>
        public string LastName { get; set; }
    }
}
