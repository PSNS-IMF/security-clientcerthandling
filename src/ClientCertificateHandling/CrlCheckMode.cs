namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Provide modes for Crl checking
    /// </summary>
    public enum CrlCheckMode
    {
        /// <summary>
        /// Check revocation status with online CRL (takes longer)
        /// </summary>
        Online = 1,
        /// <summary>
        /// Check revocation status with cached CRL
        /// </summary>
        Offline = 2
    }
}
