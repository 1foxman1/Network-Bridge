using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.Arp;
using System.Net;
using System.IO;
using System.Net.Mail;
using System.Threading;

namespace Network_Bridge
{
    public class MyDevice
    {
        private PacketDevice device;
        private List<string> addresses;
        private int id;

        public MyDevice(PacketDevice device)
        {
            this.addresses = new List<string>();
            this.device = device;
            this.id = -1;
        }

        public PacketDevice Device
        {
            get
            {
                return this.device;
            }

            set
            {
                this.device = value;
            }
        }

        public List<string> Addresses
        {
            get
            {
                return this.addresses;
            }

            set
            {
                this.addresses = value;
            }
        }

        public int ID
        {
            get
            {
                return this.id;
            }

            set
            {
                this.id = value;
            }
        }



    }
}
