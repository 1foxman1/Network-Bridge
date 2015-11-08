using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApplication16
{
    class TcpSessionValue
    {
        public int seqNum { get; set; }
        public int ackNum { get; set; }
        public int windowSize { get; set; }

        public TcpSessionValue(int seqNum, int ackNum, int windowSize)
        {
            this.seqNum = seqNum;
            this.ackNum = ackNum;
            this.windowSize = windowSize;
        }

        public override string ToString()
        {
            return ("seqNum: " + seqNum + ", ackNum: " + ackNum + ", windowSize: " + windowSize);
        }
    }
}
