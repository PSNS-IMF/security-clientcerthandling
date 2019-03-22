namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Contains constant <see cref="System.String"/> values.
    /// </summary>
    public static class Constants
    {
        /// <summary>
        /// The key to the client certificate binary string added to the HTTP header by the BigIP load balancer
        /// </summary>
        public const string F5CertificateBinaryHeaderValueName = "ssl.client_cert";

        public const string DodIdClaimTypeName = "DodId";
        public const string EmailClaimTypeName = "Email";
        public const string FirstNameClaimTypeName = "FirstName";
        public const string LastNameClaimTypeName = "LastName";
        public const string MiddleNameClaimTypeName = "MiddleName";
    }
}
