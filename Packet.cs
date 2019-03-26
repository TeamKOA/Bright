using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace Bright.net
{
    public struct Packet
    {
        public Packet(PacketType type, OPCode opcode, string username, byte[] message) : this(type: type, opcode: opcode, username: username, receiver: "", message: message) { }

        public Packet(PacketType type, OPCode opcode, string username, string receiver, byte[] message)
        {
            Type = type;
            OPCode = opcode;
            Username = username;
            Receiver = receiver;
            Message = message;
        }

        public Packet(byte[] bytes) : this(bytes: bytes, offset: 0, count: bytes.Length) { }

        public Packet(byte[] bytes, int offset, int count)
        {
            Type = (PacketType)bytes[offset + 0];
            OPCode = (OPCode)BitConverter.ToUInt16(bytes, offset + 1);

            Username = Encoding.ASCII.GetString(bytes, offset + 4, bytes[offset + 3]);
            int forehead = 4 + Username.Length;

            Receiver = Encoding.ASCII.GetString(bytes, offset + forehead + 1, bytes[offset + forehead]);
            forehead += 1 + Receiver.Length;

            Message = new byte[count - forehead];
            for (int i = 0; i < Message.Length; i++)
            {
                Message[i] = bytes[offset + i + forehead];
            }
        }

        public PacketType Type { get; set; }
        public OPCode OPCode { get; set; }
        public string Username { get; set; }
        public string Receiver { get; set; }
        public byte[] Message { get; set; }

        public byte[] GetBytes()
        {
            int forehead = 4 + Username.Length;
            byte[] bytes = new byte[Message.Length + forehead];

            bytes[0] = (byte)Type;

            byte[] temp = BitConverter.GetBytes((ushort)OPCode);
            bytes[1] = temp[0];
            bytes[2] = temp[1];

            bytes[3] = (byte)Username.Length;
            temp = Encoding.ASCII.GetBytes(Username);
            for (int i = 0; i < temp.Length; i++)
            {
                bytes[i + 4] = temp[i];
            }

            bytes[forehead] = (byte)Receiver.Length;
            temp = Encoding.ASCII.GetBytes(Receiver);
            for (int i = 0; i < temp.Length; i++)
            {
                bytes[i + forehead] = temp[i];
            }
            forehead += 1 + Receiver.Length;

            for (int i = 0; i < Message.Length; i++)
            {
                bytes[i + forehead] = Message[i];
            }

            return bytes;
        }

        public void Send(NetworkStream stream)
        {
            byte[] data = GetBytes();
            stream.Write(data, 0, data.Length);
        }

        public async void SendAsync(NetworkStream stream)
        {
            byte[] data = GetBytes();
            await stream.WriteAsync(data, 0, data.Length);
        }
    }

    public enum PacketType : byte
    {
        Disconnect = 0,
        Connect = 1,

        Send = 2,
        Receive = 3,

        Authenticate = 4,
        SignUp = 5,
        ChangeRSA = 6,
        ChangeAES = 7,

        Error = 15
    }
}
