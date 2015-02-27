using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Runtime.Serialization;

namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Used to indicate a problem with a certificate
    /// </summary>
    public class InvalidCertificateException : InvalidOperationException, ISerializable
    {
        public InvalidCertificateException() { }
        public InvalidCertificateException(string message) : base(message) { }
        public InvalidCertificateException(string message, Exception inner) 
            : base(message, inner) { }

        protected InvalidCertificateException(SerializationInfo info, StreamingContext context) 
            : base(info, context) { }
    }
}