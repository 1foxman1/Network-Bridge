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
        private string macAddress;
        private string ipAddress;

        public MyDevice(PacketDevice device, string macAddress, string ipAddress, int id)
        {
            this.addresses = new List<string>();
            this.device = device;
            this.id = id;
            this.macAddress = macAddress;
            this.ipAddress = ipAddress;
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

        public string MacAddress
        {
            get
            {
                return this.macAddress;
            }

            set
            {
                this.macAddress = value;
            }
        }

        public string IPAddress
        {
            get
            {
                return this.ipAddress;
            }

            set
            {
                this.ipAddress = value;
            }
        }



    }
}
