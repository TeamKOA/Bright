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
    public class Server
    {
        TcpListener listener;
        NetworkStream stream;
        
        RSACryptoServiceProvider serverRSA;
        RSACryptoServiceProvider clientRSA;

        AesCryptoServiceProvider serverAES;
        ICryptoTransform aesEncryptor;
        ICryptoTransform aesDecryptor;

        public void Listen(IPAddress ip, int port)
        {
            try
            {
                serverRSA = new RSACryptoServiceProvider();
                // Connect TCP
                listener = new TcpListener(ip, port);
                listener.Start();

                while (true)
                {
                    using (var client = listener.AcceptTcpClient())
                    {
                        stream = client.GetStream();

                        // RSA Handshake
                        Packet packet = ReceivePacket(stream, 512);
                        byte[] data = packet.Message;

                        int clientRN;
                        try
                        {
                            clientRSA = new RSACryptoServiceProvider();
                            clientRSA.FromXmlStringCore(Encoding.ASCII.GetString(data, 4, data.Length - 4));

                            clientRN = BitConverter.ToInt32(data, 0);
                        }
                        catch (CryptographicException e)
                        {
                            throw new CryptographicException("Client string invalid", e);
                            throw;
                        }


                        RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
                        byte[] temp = Encoding.ASCII.GetBytes(serverRSA.ToXmlStringCore(false));
                        data = new byte[4 + temp.Length];
                        temp.CopyTo(data, 4);
                        
                        temp = new byte[4];
                        random.GetBytes(temp);
                        int serverRN = BitConverter.ToInt32(temp, 0);
                        temp.CopyTo(data, 0);

                        packet = new Packet(PacketType.Connect, OPCode.ConnectSecureClient, "", data);
                        packet.Send(stream);

                        packet = ReceivePacket(stream);
                        int secret = BitConverter.ToInt32(serverRSA.Decrypt(packet.Message, true), 0);

                        using (SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider())
                        {
                            serverAES = new AesCryptoServiceProvider();
                            serverAES.Key = sha.ComputeHash(BitConverter.GetBytes(serverRN * (long)clientRN + secret));
                        }

                        // Exchange IVs
                        packet = new Packet(PacketType.Connect, OPCode.ConnectSecureClient, "", serverAES.IV);
                        packet.Send(stream);
                        aesEncryptor = serverAES.CreateEncryptor();
                        
                        packet = ReceivePacket(stream);

                        serverAES.IV = packet.Message;
                        aesDecryptor = serverAES.CreateDecryptor();
                        // Secure connection established
                        Console.WriteLine("Secure connection established");
                        Console.WriteLine(BitConverter.ToString(serverAES.Key));

                        //while (!stream.DataAvailable) { System.Threading.Thread.Sleep(10); }
                        //data = new byte[256];
                        //int count = stream.Read(data, 0, data.Length);
                        
                        Console.WriteLine(BitConverter.ToString(data));
                        packet = ReceiveEncryptedPacket(stream, aesDecryptor);
                        Console.WriteLine(packet.Username + " : " + Encoding.ASCII.GetString(packet.Message));

                        packet = new Packet(PacketType.Authenticate, OPCode.AuthenticateClient, packet.Username, Encoding.ASCII.GetBytes(Console.ReadLine()));
                        SendEncryptedPacket(stream, packet, aesEncryptor);
                    }

                }

            }
            finally
            {
                
            }
        }
    }
}
