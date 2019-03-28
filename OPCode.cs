using System;
using System.Collections.Generic;
using System.Text;

namespace Bright.net
{
    public enum OPCode : ushort
    {
        ConnectClientRN,
        ConnectServerRNKey,
        ConnectClientSecret,
        ConnectClientIV,
        ConnectServerIV,

        RequestServerCertificate,
        ServerCertificate,

        AuthenticateClient,
        AuthenticationOK,
        AuthenticationError,

        CryptographicError,
    }

    public static class CodeDescription
    {
        public static string Get(OPCode code)
        {
            switch (code)
            {
                default:
                    return "Unknown Error";
            }
        }
    }
}
