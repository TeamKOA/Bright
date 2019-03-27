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
                clientRSA = new RSACryptoServiceProvider();
                clientRSA.FromXmlStringCore(rsaXMLString);
                byte[] temp = Encoding.ASCII.GetBytes(clientRSA.ToXmlStringCore(false));
                byte[] data = new byte[4 + temp.Length];
                temp.CopyTo(data, 4);

                RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
                temp = new byte[4];
                random.GetBytes(temp);
                int clientRN = BitConverter.ToInt32(temp, 0);
                temp.CopyTo(data, 0);
                
                Packet packet = new Packet(PacketType.Connect, OPCode.ConnectSecureClient, "", data);
                packet.Send(stream);

                packet = ReceivePacket(stream, 512);
                data = packet.Message;

                if (packet.Type != PacketType.Connect)
                {
                    throw new Exception("Server rejected connection");
                }
                int serverRN;
                try
                {
                    serverRSA = new RSACryptoServiceProvider();
                    serverRSA.FromXmlStringCore(Encoding.ASCII.GetString(data, 4, data.Length - 4));

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
                temp = serverRSA.Encrypt(temp, true);
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
                Console.WriteLine("Secure connection established");
                Console.WriteLine(BitConverter.ToString(serverAES.Key));

                packet = new Packet(PacketType.Authenticate, OPCode.AuthenticateClient, username, Encoding.ASCII.GetBytes(Console.ReadLine()));
                //SendEncryptedPacket(stream, packet, aesEncryptor);
                data = EncryptPacket(packet, aesEncryptor);
                stream.Write(data, 0, data.Length);
                using (var memStream = new MemoryStream(data, 0, data.Length))
                {
                    int count = data.Length;
                    using (var cryptoStream = new CryptoStream(memStream, serverAES.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        count = cryptoStream.Read(data, 0, count);
                    }
                }
                Console.WriteLine(BitConverter.ToString(data));

                packet = ReceiveEncryptedPacket(stream, aesDecryptor);
                Console.WriteLine(packet.Username + " : " + Encoding.ASCII.GetString(packet.Message));
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

        public Client(string username, string rsaXMLString)
        {
            this.username = username;
            this.rsaXMLString = rsaXMLString;
        }
    }
}
