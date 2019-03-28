using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Security.Cryptography;

namespace Bright.net
{
    public struct Certificate
    {
        public string ID { get; set; }
        public DateTime Time { get; set; }
        public byte[] Data { get; set; }
        public byte[] Signature { get; set; }

        public Certificate(string id, byte[] data, DateTime time)
        {
            ID = id;
            Data = data;
            Signature = new byte[0];
            Time = time;
        }
        public Certificate(string id, byte[] data) : this(id, data, DateTime.UtcNow) { }

        public Certificate(byte[] bytes)
        {
            Time = new DateTime(BitConverter.ToInt64(bytes, 0) * 10000000 + new DateTime(1970, 1, 1, 0, 0, 0).Ticks);

            ID = Encoding.ASCII.GetString(bytes, 0, bytes[8]);
            int index = 9 + ID.Length;

            Data = new byte[bytes[index++]];
            for (int i = 0; i < Data.Length; i++)
            {
                Data[i] = bytes[index++];
            }

            Signature = new byte[bytes.Length - index];
            for (int i = 0; i < Data.Length; i++)
            {
                Signature[i] = bytes[index + i];
            }
        }
        
        public byte[] GetBytes()
        {
            byte[] bytes = new byte[10 + ID.Length + Signature.Length + Data.Length];

            BitConverter.GetBytes((Time.Ticks - new DateTime(1970, 1, 1, 0, 0, 0).Ticks) / 10000000).CopyTo(bytes, 0);

            bytes[8] = (byte)ID.Length;
            Encoding.ASCII.GetBytes(ID, 0, ID.Length, bytes, 9);
            int index = 9 + ID.Length;

            bytes[index] = (byte)Data.Length;
            Data.CopyTo(bytes, ++index);

            index += Data.Length;
            Signature.CopyTo(bytes, index);

            return bytes;
        }

        public byte[] GetSignedBytes()
        {
            byte[] bytes = new byte[10 + ID.Length + Data.Length];

            BitConverter.GetBytes((Time.Ticks - new DateTime(1970, 1, 1, 0, 0, 0).Ticks) / 10000000).CopyTo(bytes, 0);

            bytes[8] = (byte)ID.Length;
            Encoding.ASCII.GetBytes(ID, 0, ID.Length, bytes, 9);
            int index = 9 + ID.Length;

            bytes[index] = (byte)Data.Length;
            Data.CopyTo(bytes, ++index);

            return bytes;
        }

        public void Sign(RSACryptoServiceProvider rsaCSP)
        {
            Signature = rsaCSP.SignData(GetSignedBytes(), HashAlgorithmName.SHA1);
        }

        public bool Verify(RSACryptoServiceProvider rsaCSP)
        {
            return rsaCSP.VerifyData(GetSignedBytes(), HashAlgorithmName.SHA1, Signature);
        }
    }
}
