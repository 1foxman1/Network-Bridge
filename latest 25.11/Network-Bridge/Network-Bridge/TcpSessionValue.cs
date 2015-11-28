using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Network_Bridge
{
    class TcpSessionValue
    {
        public uint seqNum { get; set; }
        public uint ackNum { get; set; }
        public int windowSize { get; set; }
        public uint prevseq { get; set; }

        public TcpSessionValue(uint seqNum, uint ackNum, int windowSize, uint prevseq)
        {
            this.seqNum = seqNum;
            this.ackNum = ackNum;
            this.windowSize = windowSize;
            this.prevseq = prevseq;
        }

        public override string ToString()
        {
            return ("seqNum: " + seqNum + ", ackNum: " + ackNum + ", windowSize: " + windowSize);
        }
    }
}
