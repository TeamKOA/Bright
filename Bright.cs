using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Bright.net
{
    public static class Bright
    {
        public static Packet ReceivePacket(NetworkStream stream, int bufferSize = 256)
        {
            while (!stream.DataAvailable) { System.Threading.Thread.Sleep(10); }
            byte[] data = new byte[bufferSize];
            int count = stream.Read(data, 0, data.Length);
            return new Packet(data, 0, count);
        }

        public static Packet ReceiveEncryptedPacket(NetworkStream stream, ICryptoTransform decryptor, int bufferSize = 256)
        {
            while (!stream.DataAvailable) { System.Threading.Thread.Sleep(10); }
            byte[] data = new byte[bufferSize];
            int count = stream.Read(data, 0, data.Length);

            using (var memStream = new MemoryStream(data, 0, count))
            {
                using (var cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read))
                {
                    count = cryptoStream.Read(data, 0, count);
                }
            }

            return new Packet(data, 0, count);
        }

        public static byte[] EncryptPacket(Packet packet, ICryptoTransform encryptor)
        {
            byte[] data;
            using (var memStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                {
                    data = packet.GetBytes();
                    cryptoStream.Write(data, 0, data.Length);

                    cryptoStream.Close();
                    data = memStream.ToArray();
                    memStream.Close();
                }
            }

            return data;
        }

        public static void SendEncryptedPacket(NetworkStream stream, Packet packet, ICryptoTransform encryptor)
        {
            byte[] data = EncryptPacket(packet, encryptor);
            stream.Write(data, 0, data.Length);
        }
    }
}
