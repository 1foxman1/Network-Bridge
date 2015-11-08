using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApplication16
{
    class TcpSessionKey
    {

        public string SrcIP { get; set; }
        public int SrcPort { get; set; }
        public string DestIP { get; set; }
        public int DestPort { get; set; }

        public TcpSessionKey(string srcIP, int SrcPort, string DestIP, int DestPort)
        {
            this.SrcIP = srcIP;
            this.SrcPort = SrcPort;
            this.DestIP = DestIP;
            this.DestPort = DestPort;
        }

        public override bool Equals(System.Object obj)
        {
            // If parameter is null return false.
            if (obj == null)
            {
                return false;
            }

            // If parameter cannot be cast to Point return false.
            TcpSessionKey session = obj as TcpSessionKey;
            if ((System.Object)session == null)
            {
                return false;
            }

            // Return true if the fields match:
            return (session.DestIP == this.DestIP && session.DestPort == this.DestPort)
                && (session.SrcIP == this.SrcIP && session.SrcPort == this.SrcPort);
        }


        public override int GetHashCode()
        {

            return this.SrcIP.GetHashCode() ^ this.SrcPort ^ this.DestIP.GetHashCode() ^ this.DestPort;
        }

        public override string ToString()
        {
            return ("SrcIP: " + SrcIP + ", SrcPort: " + SrcPort + ", DestIP: " + DestIP + ",DestPort: " + DestPort + ",");
        }

    }


    
 
}
