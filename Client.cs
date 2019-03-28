using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.IO;

using static Bright.net.Bright;

namespace Bright.net
{
    public class Client
    {
        readonly string username;
        readonly string rsaXMLString;
        readonly string serverSignatureString;

        TcpClient client;
        NetworkStream stream;

        ICryptoTransform aesEncryptor;
        ICryptoTransform aesDecryptor;

        string serverSessionRSA;
        
        public void Connect(string hostname, int port)
        {
            try
            {
                // Connect TCP
                client = new TcpClient(hostname, port);
                stream = client.GetStream();
                byte[] data, temp;

                // RSA Handshake
                //clientRSA = new RSACryptoServiceProvider();
                //clientRSA.FromXmlStringCore(rsaXMLString);
                //temp = Encoding.ASCII.GetBytes(clientRSA.ToXmlStringCore(false));
                //data = new byte[4 + temp.Length];
                //temp.CopyTo(data, 4);

                RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
                temp = new byte[4];
                random.GetBytes(temp);
                int clientRN = BitConverter.ToInt32(temp, 0);
                //temp.CopyTo(data, 0);
                
                Packet packet = new Packet(PacketType.Connect, OPCode.ConnectClientRN, "", temp);
                packet.Send(stream);

                packet = ReceivePacket(stream, 512);
                data = packet.Message;

                if (packet.Type != PacketType.Connect)
                {
                    throw new Exception("Server rejected connection");
                }
                int serverRN;
                int secret;
                using (RSACryptoServiceProvider serverRSA = new RSACryptoServiceProvider())
                {
                    try
                    {
                        serverSessionRSA = Encoding.ASCII.GetString(data, 4, data.Length - 4);
                        serverRSA.FromXmlStringCore(serverSessionRSA);

                        serverRN = BitConverter.ToInt32(data, 0);
                    }
                    catch (CryptographicException e)
                    {
                        throw new CryptographicException("Server string invalid", e);
                        throw;
                    }

                    temp = new byte[4];
                    random.GetBytes(temp);
                    secret = BitConverter.ToInt32(temp, 0);
                    temp = serverRSA.Encrypt(temp, true); 
                }
                packet = new Packet(PacketType.Connect, OPCode.ConnectClientSecret, "", temp);
                packet.Send(stream);

                using (AesCryptoServiceProvider serverAES = new AesCryptoServiceProvider())
                {
                    using (SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider())
                    {
                        serverAES.Key = sha.ComputeHash(BitConverter.GetBytes(clientRN * (long)serverRN + secret));
                    }

                    // Exchange IVs
                    packet = ReceivePacket(stream);

                    serverAES.IV = packet.Message;
                    aesDecryptor = serverAES.CreateDecryptor();

                    serverAES.GenerateIV();
                    packet = new Packet(PacketType.Connect, OPCode.ConnectClientIV, "", serverAES.IV);
                    packet.Send(stream);
                    aesEncryptor = serverAES.CreateEncryptor(); 
                }
                // Secure connection established
                Console.WriteLine("Secure connection established");
                

            }
            finally
            {
                Dispose();
            }
        }

        public bool CheckServer()
        {
            try
            {
                Packet packet = new Packet(PacketType.Authenticate, OPCode.RequestServerCertificate, "", new byte[0]);
                SendEncryptedPacket(packet);

                packet = ReceiveEncryptedPacket();
                if (packet.Type == PacketType.Authenticate && packet.OPCode == OPCode.ServerCertificate)
                {
                    Certificate certificate = new Certificate(packet.Message);
                    if (Encoding.ASCII.GetString(certificate.Data) != serverSessionRSA || DateTime.UtcNow.Subtract(certificate.Time).TotalMinutes > 1)
                        return false;

                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        rsa.FromXmlStringCore(serverSignatureString);
                        return certificate.Verify(rsa);
                    }
                }
                return false;
            }
            catch (Exception)
            {
                return false;
            }
            finally
            {
                Dispose();
            }
        }

        public OPCode Authenticate()
        {
            try
            {
                Certificate certificate = new Certificate(username, new byte[0]);
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlStringCore(rsaXMLString);
                    certificate.Sign(rsa);
                }
                Packet packet = new Packet(PacketType.Authenticate, OPCode.AuthenticateClient, username, certificate.GetBytes());
                SendEncryptedPacket(packet);

                packet = ReceiveEncryptedPacket();
                if (packet.Type != PacketType.Authenticate)
                    return OPCode.AuthenticationError;

                return packet.OPCode;
            }
            finally
            {
                Dispose();
            }
        }

        public Client(string username, string rsaXMLString)
        {
            this.username = username;
            this.rsaXMLString = rsaXMLString;
        }

        private void SendEncryptedPacket(Packet packet)
        {
            Bright.SendEncryptedPacket(stream, packet, aesEncryptor);
        }
        private Packet ReceiveEncryptedPacket(int bufferSize = 256)
        {
            return Bright.ReceiveEncryptedPacket(stream, aesDecryptor, bufferSize);
        }

        private void Dispose()
        {
            client.Close();
            stream.Dispose();
            aesEncryptor.Dispose();
            aesDecryptor.Dispose();
        }
    }
}
