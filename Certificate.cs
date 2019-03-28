using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Net;

namespace Bright.net
{
    public struct Certificate
    {
        public string ID { get; set; }
        public DateTime Time { get; set; }
        public byte[] Data { get; set; }

        public Certificate(string id, byte[] data, DateTime time)
        {
            ID = id;
            Data = data;
            Time = time;
        }
        public Certificate(string id, byte[] data) : this(id, data, DateTime.UtcNow) { }
        
        public byte[] GetBytes()
        {

        }
    }
}
