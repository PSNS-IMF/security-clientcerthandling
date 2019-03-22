using Psns.Common.Functional;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

using static Psns.Common.Functional.Prelude;
using static Psns.Common.Security.ClientCertificateHandling.Constants;

namespace Psns.Common.Security.ClientCertificateHandling
{
    /// <summary>
    /// Basic properties of every DodUser
    /// </summary>
    public struct DodUser
    {
        /// <summary>
        /// The DodId/EDIPI
        /// </summary>
        public readonly string DodId;

        /// <summary>
        /// First Name
        /// </summary>
        public readonly Maybe<string> FirstName;

        /// <summary>
        /// Middle Name
        /// </summary>
        public readonly Maybe<string> MiddleName;

        /// <summary>
        /// Last Name
        /// </summary>
        public readonly Maybe<string> LastName;

        /// <summary>
        /// Email
        /// </summary>
        public readonly Maybe<string> EmailAddress;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="dodId"></param>
        /// <param name="firstName"></param>
        /// <param name="middleName"></param>
        /// <param name="lastName"></param>
        /// <param name="email"></param>
        /// <exception cref="ArgumentNullException">When <paramref name="dodId"/> is null or empty</exception>
        public DodUser(string dodId, Maybe<string> firstName, Maybe<string> middleName, Maybe<string> lastName, Maybe<string> email)
        {
            if (string.IsNullOrEmpty(dodId))
                throw new ArgumentNullException(nameof(dodId), $"{nameof(dodId)} must have a value");

            DodId = dodId.AssertValue();
            FirstName = firstName;
            MiddleName = middleName;
            LastName = lastName;
            EmailAddress = email;
        }

        /// <summary>
        /// A formatted string for this.
        /// </summary>
        /// <returns></returns>
        public override string ToString() =>
            $@"{{{nameof(DodId)}: {DodId}, {nameof(FirstName)}: {FirstName}, {nameof(LastName)}: {
                LastName}, {nameof(MiddleName)}: {MiddleName}, {nameof(EmailAddress)}: {EmailAddress}}}";
    }

    /// <summary>
    /// Some <see cref="DodUser"/> extensions.
    /// </summary>
     public static class DodUserExtentions
    {
        /// <summary>
        /// Create a <see cref="DodUser" /> with just a <paramref name="dodId"/>.
        /// </summary>
        /// <param name="dodId"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">When <paramref name="dodId"/> is null or empty</exception>
        public static DodUser FromDodId(string dodId) =>
            new DodUser(dodId, None, None, None, None);

        /// <summary>
        /// Assign <paramref name="dodId"/> to <paramref name="self"/>.
        /// </summary>
        /// <param name="self"></param>
        /// <param name="dodId"></param>
        /// <returns></returns>
        public static DodUser WithDodId(this DodUser self, string dodId) =>
            new DodUser(dodId, self.FirstName, self.LastName, self.MiddleName, self.EmailAddress);

        /// <summary>
        /// Assign <paramref name="firstName"/> to <paramref name="self"/>.
        /// </summary>
        /// <param name="self"></param>
        /// <param name="firstName"></param>
        /// <returns></returns>
        public static DodUser WithFirstName(this DodUser self, string firstName) =>
            new DodUser(self.DodId, firstName, self.MiddleName, self.LastName, self.EmailAddress);

        /// <summary>
        /// Assign <paramref name="lastName"/> to <paramref name="self"/>.
        /// </summary>
        /// <param name="self"></param>
        /// <param name="lastName"></param>
        /// <returns></returns>
        public static DodUser WithLastName(this DodUser self, string lastName) =>
            new DodUser(self.DodId, self.FirstName, self.MiddleName, lastName, self.EmailAddress);

        /// <summary>
        /// Assign <paramref name="middleName"/> to <paramref name="self"/>.
        /// </summary>
        /// <param name="self"></param>
        /// <param name="middleName"></param>
        /// <returns></returns>
        public static DodUser WithMiddleName(this DodUser self, string middleName) =>
            new DodUser(self.DodId, self.FirstName, middleName, self.LastName, self.EmailAddress);

        /// <summary>
        /// Assign <paramref name="email"/> to <paramref name="self"/>.
        /// </summary>
        /// <param name="self"></param>
        /// <param name="email"></param>
        /// <returns></returns>
        public static DodUser WithEmail(this DodUser self, string email) =>
            new DodUser(self.DodId, self.FirstName, self.MiddleName, self.LastName, email);

        /// <summary>
        /// Generates <see cref="Claim"/>s from a <see cref="DodUser"/>.
        /// </summary>
        /// <param name="self"></param>
        /// <returns></returns>
        public static IEnumerable<Claim> AsClaims(this DodUser self) =>
            Cons(
                (FirstNameClaimTypeName, self.FirstName),
                (LastNameClaimTypeName, self.LastName),
                (MiddleNameClaimTypeName, self.MiddleName),
                (EmailClaimTypeName, self.EmailAddress),
                (DodIdClaimTypeName, self.DodId))
                .Aggregate(
                    Empty<Claim>(),
                    (claims, next) =>
                        next.Item2.Match(
                            some: typeVal => claims.Append(tail: new Claim(next.Item1, typeVal)),
                            none: () => claims));
    }
}
