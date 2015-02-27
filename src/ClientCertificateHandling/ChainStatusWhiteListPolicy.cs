using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Web;
using System.Security.Cryptography.X509Certificates;

namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Any items added to the white list will be ignored when checking the Certificate Chain.
    /// The status X509ChainStatusFlags.NoError will always be in the list.
    /// </summary>
    public class ChainStatusWhiteListPolicy
    {
        static HashSet<X509ChainStatusFlags> _whiteList = 
            new HashSet<X509ChainStatusFlags> 
            { 
                X509ChainStatusFlags.NoError 
            };

        /// <summary>
        /// The current white list
        /// </summary>
        public static HashSet<X509ChainStatusFlags> Current
        {
            get
            {
                return _whiteList;
            }
        }

        /// <summary>
        /// Add and new exception to the certifcation chain validation white list
        /// </summary>
        /// <param name="flag">The flag to be excepted</param>
        public static void Add(X509ChainStatusFlags flag)
        {
            _whiteList.Add(flag);
        }
    }
}
