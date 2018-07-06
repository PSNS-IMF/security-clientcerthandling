using System;

namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Used to indicate a problem with a certificate
    /// </summary>
    public class InvalidCertificateException : InvalidOperationException
    {
        /// <summary>
        /// 
        /// </summary>
        public InvalidCertificateException() { }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        public InvalidCertificateException(string message) : base(message) { }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        /// <param name="inner"></param>
        public InvalidCertificateException(string message, Exception inner)
            : base(message, inner) { }
    }
}