using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.IO;

namespace Bright.net
{
    public class Client
    {
        private string username;

        TcpClient client;
        NetworkStream stream;

        string rsaXMLString;
        RSACryptoServiceProvider clientRSA;
        RSACryptoServiceProvider serverRSA;

        AesCryptoServiceProvider serverAES;
        ICryptoTransform aesEncryptor;
        ICryptoTransform aesDecryptor;

        CryptoStream writeStream;
        CryptoStream readStream;
        
        public void Connect(string hostname, int port)
        {
            try
            {
                // Connect TCP
                client = new TcpClient(hostname, port);
                stream = client.GetStream();

                // RSA Handshake
                RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
                byte[] temp = new byte[4];
                byte[] data = new byte[4 + temp.Length];
                random.GetBytes(temp);
                int clientRN = BitConverter.ToInt32(temp, 0);
                temp.CopyTo(data, 0);

                clientRSA = new RSACryptoServiceProvider();
                clientRSA.FromXmlString(rsaXMLString);
                temp = Encoding.ASCII.GetBytes(clientRSA.ToXmlString(false));
                temp.CopyTo(data, 4);

                Packet packet = new Packet(PacketType.Connect, OPCode.ConnectSecureClient, "", data);
                packet.Send(stream);

                packet = ReceivePacket(stream);
                data = packet.Message;

                if (packet.Type != PacketType.Connect)
                {
                    throw new Exception("Server rejected connection");
                }
                int serverRN;
                try
                {
                    serverRSA = new RSACryptoServiceProvider();
                    serverRSA.FromXmlString(Encoding.ASCII.GetString(data, 4, data.Length - 4));

                    serverRN = BitConverter.ToInt32(data, 0);
                }
                catch (CryptographicException e)
                {
                    throw new CryptographicException("Server string invalid", e);
                    throw;
                }

                temp = new byte[4];
                random.GetBytes(temp);
                int secret = BitConverter.ToInt32(temp, 0);
                packet = new Packet(PacketType.Connect, OPCode.ConnectSecureClient, "", temp);
                packet.Send(stream);

                using (SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider())
                {
                    serverAES = new AesCryptoServiceProvider();
                    serverAES.Key = sha.ComputeHash(BitConverter.GetBytes(clientRN * (long)serverRN + secret));
                }

                // Exchange IVs
                packet = ReceivePacket(stream);
                
                serverAES.IV = packet.Message;
                aesDecryptor = serverAES.CreateDecryptor();

                serverAES.GenerateIV();
                packet = new Packet(PacketType.Connect, OPCode.ConnectSecureClient, "", serverAES.IV);
                packet.Send(stream);
                aesEncryptor = serverAES.CreateEncryptor();

                readStream = new CryptoStream(stream, aesDecryptor, CryptoStreamMode.Read);
                writeStream = new CryptoStream(stream, aesEncryptor, CryptoStreamMode.Write);
                // Secure connection established

            }
            catch (Exception)
            {

                throw;
            }
            finally
            {
                client.Close();
            }
        }
        
        private Packet ReceivePacket(Stream stream, int bufferSize = 256)
        {
            byte[] data = new byte[bufferSize];
            int count = stream.Read(data, 0, data.Length);
            return new Packet(data, 0, count);
        }
    }
}
