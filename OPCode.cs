﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Bright.net
{
    public enum OPCode : ushort
    {
        ConnectSecureClient,
        ConnectSecureServer,
        AuthenticateClient,
        AuthenticationOK,
        AuthenticationError
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
