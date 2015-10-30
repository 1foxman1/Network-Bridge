using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.Arp;
using System.Net;
using System.IO;
using System.Net.Mail;
using System.Threading;
using SharpPcap;
using System.Net.NetworkInformation;

namespace Network_Bridge
{
    public class MyDevice
    {
        private PacketDevice device;
        private ICaptureDevice capDevice;
        private PacketCommunicator communicator;
        private List<Address> switchAddresses;
        private List<Address> computerAddresses;
        private int id;
        private string macAddress;
        private string ipAddress;

        public MyDevice(PacketDevice device, string macAddress, string ipAddress, int id, ICaptureDevice capDevice, PacketCommunicator communicator)
        {
            this.switchAddresses = new List<Address>();
            this.computerAddresses = new List<Address>();
            this.device = device;
            this.id = id;
            this.macAddress = macAddress;
            this.ipAddress = ipAddress;
            this.capDevice = capDevice;
            this.communicator = communicator;


        }

        public string MacAddressWithDots()
        {
                string newMac = this.macAddress;
                for (int i = 2; i < this.macAddress.Length + 3; i += 3)
                {
                    newMac = newMac.Insert(i, ":");
                }
                return newMac;

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

        public List<Address> SwitchAddresses
        {
            get
            {
                return this.switchAddresses;
            }

            set
            {
                this.switchAddresses = value;
            }
        }

        public List<Address> ComputerAddresses
        {
            get
            {
                return this.computerAddresses;
            }

            set
            {
                this.computerAddresses = value;
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

        public ICaptureDevice CapDevice
        {
            get
            {
                return this.capDevice;
            }

            set
            {
                this.capDevice = value;
            }
        }

        public PacketCommunicator Communicator  
        {
            get
            {
                return this.communicator;
            }

            set
            {
                this.communicator = value;
            }
        }
    }
}
