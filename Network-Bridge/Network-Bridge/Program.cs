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
using PcapDotNet.Packets.Icmp;
using System.Net;
using System.IO;
using System.Net.Mail;
using System.Threading;
using SharpPcap;
using System.Net.NetworkInformation;
namespace Network_Bridge
{
    class Program
    {
        public static string LocalIPAddress()
        {
            IPHostEntry host;
            string localIP = "";
            host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily.ToString() == "InterNetwork")
                {
                    localIP = ip.ToString();
                    break;
                }
            }
            return localIP;
        }

        private static int deviceNumber; //Global integer to pass on between threads
        private static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine; // global list of all devices
        private static List<MyDevice> myDevices = new List<MyDevice>();
        private static bool isFirstP = true;

        //Capture thread
        public static void CaptureStarter()
        {
            // Take the selected adapter
            PacketDevice selectedDevice = allDevices[deviceNumber];

            //Console.WriteLine("Gal device name: " + selectedDevice.Name);
            //Console.WriteLine("Gal device tostring: " + selectedDevice.ToString());
            ////foreach (DeviceAddress addr in selectedDevice.Addresses)
            ////{
            //    Console.WriteLine("Gal device addr: " +  addr.Address.ToString());
            //    if (addr.Destination != null)
            //        Console.WriteLine(addr.Destination.ToString());
            //}


            int threadID = System.Threading.Thread.CurrentThread.ManagedThreadId; //fetch current thread ID

            CaptureDeviceList devices = CaptureDeviceList.Instance;

            string dName = selectedDevice.Name;
            dName = dName.Substring(dName.IndexOf('{') + 1, (dName.IndexOf('}') - dName.IndexOf('{') - 1));
            string dAddress = "";
            ICaptureDevice capDevice = null;
            foreach (ICaptureDevice dev in devices)
            {
                dev.Open();

                string name = dev.Name;
                name = name.Substring(name.IndexOf('{') + 1, (name.IndexOf('}') - name.IndexOf('{') - 1));
                if (dName.Equals(name))
                {
                    dAddress = dev.MacAddress.ToString();
                    capDevice = dev;
                }
            }

            string deviceIP = selectedDevice.Addresses[1].Address.ToString();
            deviceIP = deviceIP.Split(' ')[1];

            Console.WriteLine("DEVICE IP: " + deviceIP);

            

            

            // Open the device
            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture                                                                           // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                MyDevice device = new MyDevice(selectedDevice, dAddress, deviceIP, threadID, capDevice, communicator);
                myDevices.Add(device);

                //Console.WriteLine("Dev ID:" + device.ID);
                //Console.WriteLine("Dev Name:" + device.Device.Name);
                //Console.WriteLine("Dev MAC: " + device.MacAddress);

                using (BerkeleyPacketFilter filter = communicator.CreateFilter("icmp or arp"))
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }

                Console.WriteLine("Listening on device " + (deviceNumber + 1) + " out of " + allDevices.Count + " :  " + selectedDevice.Description + "...");

                // Start the capture

                communicator.ReceivePackets(0, PacketHandler);
                
            }
        }

        // Callback function invoked by Pcap.Net for every incoming packet
        private static void PacketHandler(Packet packet)
        {
              
            if (myDevices[0].IPAddress != packet.IpV4.Source.ToString())
            {
                //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length + "IP:" + packet.IpV4);

                int threadID = System.Threading.Thread.CurrentThread.ManagedThreadId; //fetch current thread ID
                MyDevice devObj = GetMacDeviceByTreadId(threadID);
                EthernetDatagram ed = packet.Ethernet;

                //Console.WriteLine("MY PACKET: " + packet.IpV4.Protocol);
                //Console.WriteLine("ICMP TEMPLATE: " + IpV4Protocol.InternetControlMessageProtocol);
                //try
                //{
                //    Console.WriteLine("VARIABLE: " + packet.IpV4.Icmp.Variable);
                //    //Console.WriteLine("PROTOCOL OPERATION: " + packet .Ethernet.Arp.GetType());
                //    //Console.WriteLine("PROTOCOL OPER: " + packet.IpV4.Icmp.GetType());
                //    //Console.WriteLine("DATALINK : " + packet.DataLink);
                //}
                //catch
                //{
                //}
                //Console.WriteLine("new option : " + packet.IpV4.Payload.GetType().TypeHandle);
                //packet.IpV4.Protocol == IpV4Protocol.InternetControlMessageProtocol

                if (ed.EtherType == (EthernetType)0x0806)//Checking if the packet type is arp
                {

                    Console.WriteLine("ARP Packet");
                    //Console.WriteLine("TARGET ADDRESS: " + packet.Ethernet.Arp.TargetProtocolIpV4Address);
                    //Console.WriteLine("DEST: " + packet.IpV4.Destination);
                    //IPAddress ipSrc = IPAddress.Parse(packet.Ethernet.Arp.TargetProtocolIpV4Address);
                    isFirstP = false;
                    //Console.WriteLine("HARA: " + packet.Ethernet.Arp.TargetProtocolIpV4Address.ToString());
                    if (CheckAddress(packet,"Arp"))
                    {
                        string SrcMac = packet.Ethernet.Source.ToString();
                        PhysicalAddress pySrc = PhysicalAddress.Parse(devObj.MacAddress);
                        PhysicalAddress pyDest = PhysicalAddress.Parse(RemoveDots(SrcMac));
                        //IPAddress ipSrc = IPAddress.Parse(devObj.IPAddress);

                        IPAddress ipSrc = null;

                        IPAddress ipDest = IPAddress.Parse(packet.IpV4.Source.ToString());

                        try
                        {
                            ipSrc = IPAddress.Parse(packet.Ethernet.Arp.TargetProtocolIpV4Address.ToString());
                        }
                        catch (Exception e)
                        {
                        }

                        //Console.WriteLine("PY-SRC: " + pySrc + ", PY-DST: " + pyDest + ", iP-SRC: " + ipSrc + ", IP-DST: " + ipDest);

                        SendResponse(pySrc, pyDest, ipDest, ipSrc);
                    }
                }
                else//packet type is icmp
                {
                    Console.WriteLine("ICMP Packet: " + packet.Length);
                    MyDevice newDev = null;

                    foreach (MyDevice dev in myDevices)
                    {
                        if (dev.ID != threadID)
                        {
                            newDev = dev;
                        }
                    }

                    CheckAddress(packet, "Icmp");

                    if (!packet.IpV4.Source.ToString().Equals("0.0.0.0") || !packet.IpV4.Destination.ToString().Equals("0.0.0.0"))
                    {

                        Console.WriteLine("Device: " + newDev.ID + "ICMP Addresses list count: " + newDev.ComputerAddresses.Count);

                        Address addr = null;
                        foreach (Address address in newDev.ComputerAddresses)
                        {
                            Console.WriteLine("IP: " + address.Ip + " ARP: " + address.Mac + " packet ip: " + packet.Ethernet.IpV4.Destination + " Packet source: " + packet.Ethernet.IpV4.Source);
                            Console.WriteLine("IP:" + address.Ip);
                            Console.WriteLine("packet IP:" + packet.Ethernet.IpV4.Destination);

                            if (address.Ip.Equals(packet.Ethernet.IpV4.Destination.ToString()))
                            {
                                Console.WriteLine("EQUALSS :>");
                                addr = address;
                            }
                        }

                        EthernetLayer ethLayer = null;
                        //MacAddress kak = new MacAddress("df:0f:34:d0:54:0a");
                        if (addr != null)
                        {
                            Console.WriteLine("ADDR: " + addr.Mac.ToString());
                            //ethLayer = packet.Ethernet.Payload.ExtractLayer() as EthernetLayer;
                            //ethLayer.Destination = kak;
                            //packet.clo  = new MacAddress(newDev.MacAddressWithDots());

                            ethLayer = new EthernetLayer { Source = new MacAddress(newDev.MacAddressWithDots()), Destination = new MacAddress(addr.Mac) };
                            Console.WriteLine("%%%%Src: " + newDev.MacAddressWithDots() + " Dst: " + addr.Mac);
                        }

                        IpV4Layer ipLayer = (IpV4Layer)packet.Ethernet.IpV4.ExtractLayer();

                        string packetType = "REQUEST";
                        try
                        {
                            IcmpEchoLayer test = (IcmpEchoLayer)packet.Ethernet.IpV4.Icmp.ExtractLayer();
                        }
                        catch
                        {
                            packetType = "REPLY";
                        }
                        // PayloadLayer payload = (PayloadLayer)packet.Ethernet.Payload.ExtractLayer();
                        ////IcmpEchoLayer icmpLayer = (IcmpEchoLayer)packet.Ethernet.IpV4.Icmp.ExtractLayer();
                        //icmpLayer.Checksum = null;
                        //Console.Write(payload.Data);
                        //Console.WriteLine("ETHER LAYER DESTINATION: " + ethLayer.Destination);
                        if (ethLayer != null && ipLayer != null)//&& payload != null)
                        {
                            Packet newPacket = BuildIcmpPacket(new MacAddress(newDev.MacAddressWithDots()), new MacAddress(addr.Mac), packet.Ethernet.IpV4.Source, packet.Ethernet.IpV4.Destination, packetType);
                            //Packet newPacket = PacketBuilder.Build(DateTime.Now, ethLayer, ipLayer, icmpLayer);
                            if (newPacket.IsValid)
                            {
                                if (newPacket.Ethernet.Source != newPacket.Ethernet.Destination)
                                {
                                    newDev.Communicator.SendPacket(newPacket);
                                    Console.WriteLine("Icmp Packet Sent");
                                }
                            }
                            else
                                Console.WriteLine("ICMP Packet Is Not Valid :(");
                        }
                    }
                    
                }
            }
        }

        
        private static string RemoveDots(string srcMac) 
        {
            string[] s = srcMac.Split(':');
            return String.Join("", s);         
        }

        private static MyDevice GetMacDeviceByTreadId(int threadID)
        {
            foreach (MyDevice devObj in myDevices)
            {
                if (devObj.ID == threadID)
                    return devObj;
            }
            return null;
        }

        private static bool CheckAddress(Packet packet, string type)
        {
            int threadID = System.Threading.Thread.CurrentThread.ManagedThreadId; //fetch current thread ID
            string mac = packet.Ethernet.Source.ToString();
            string ip = packet.Ethernet.IpV4.Source.ToString();

            MyDevice md;
            foreach (MyDevice device in myDevices) //checks if it's a new device or if a mac should be added
            {
                //Console.WriteLine("Device" + device.ID + " Count: " + device.Addresses.Count);
                if (device.ID == threadID) //found device
                {
                    bool inList = false;
                    md = device;
                    
                    List<Address> checkAddressesList = device.SwitchAddresses;
                    if (type.Equals("Icmp"))
                    {
                        checkAddressesList = device.ComputerAddresses;
                    }

                    foreach (Address address in checkAddressesList)
                    {
                        if (address.Mac.Equals(mac))
                        {                    
                            inList = true;             
                        }
                    }

                    if (!inList)
                    {
                        //Console.WriteLine("Device Address: " + device.Address);
                        if (type.Equals("Arp"))
                        {
                            device.SwitchAddresses.Add(new Address(ip, mac)); // if device mac not in list, adds it
                            Console.WriteLine(">>New Arp Connection: Switch IP: " + ip + " Switch Mac address: " + mac + " Added from device: " + device.ID);
                        }
                        else
                        {
                            device.ComputerAddresses.Add(new Address(ip, mac));
                            Console.WriteLine(">>>New Computer Icmp Connection: IP: " + ip + " Mac address: " + mac + " Added from device: " + device.ID);
                        }

                        
                        return true;
                    }

                }

            }
            return false;
        }


        private static void SendResponse(System.Net.NetworkInformation.PhysicalAddress pysSrc,
                System.Net.NetworkInformation.PhysicalAddress pysdest,
                IPAddress destAddrIp,
                IPAddress myAddrIp)
        {
            CaptureDeviceList devices = CaptureDeviceList.Instance;
            foreach (ICaptureDevice dev in devices)
            {
                dev.Open();

                //System.Net.NetworkInformation.PhysicalAddress pysSrc = null;
                //System.Net.NetworkInformation.PhysicalAddress pysdest = null;
                //IPAddress destAddrIp = new IPAddress(null);
                //IPAddress myAddrIp = new IPAddress(null);

                try
                {
                    var ethernetPacket = new PacketDotNet.EthernetPacket(pysSrc, pysdest, PacketDotNet.EthernetPacketType.Arp);

                    var arpPacket = new PacketDotNet.ARPPacket(PacketDotNet.ARPOperation.Response, pysdest, destAddrIp, pysSrc, myAddrIp);
                    ethernetPacket.PayloadPacket = arpPacket;

                    dev.SendPacket(ethernetPacket);
                }
                catch (Exception e)
                {
                }

                
            }
        }
        

        static void Main(string[] args)
        {

            //Opens thread for every device, to capture traffic from all devices.
            Thread[] recievers = new Thread[allDevices.Count];
            Thread.Sleep(100);
            for (int i = 0; i < allDevices.Count; i++)
            {
                deviceNumber = i;                               // sets global integer to device number to pass it on to the right thread
                recievers[i] = new Thread(CaptureStarter);     //creates thread
                recievers[i].Start();                           // starts thread
                Thread.Sleep(100);                               //thread sleeps for a while to let the just opened thread to finish it's initialisation
            }
        }

        private static Packet BuildIcmpPacket(MacAddress SourceMac, MacAddress DestinationMac, IpV4Address SourceIp, IpV4Address CurrentDestination, string packetType)
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    //Source = new MacAddress("01:01:01:01:01:01"),
                    //Destination = new MacAddress("02:02:02:02:02:02"),

                    Source = SourceMac,
                    Destination = DestinationMac,
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    //Source = new IpV4Address("1.2.3.4"),
                    //CurrentDestination = new IpV4Address("11.22.33.44"),
                    Source = SourceIp,
                    CurrentDestination = CurrentDestination,
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            IcmpEchoLayer icmpLayer = null;
            IcmpEchoReplyLayer icmpRLayer = null;

            PacketBuilder builder = null;

            if (packetType.Equals("REQUEST"))
            {
                Console.WriteLine("Request");
                icmpLayer =
                    new IcmpEchoLayer
                    {
                        Checksum = null, // Will be filled automatically.
                        Identifier = 456,
                        SequenceNumber = 800,
                    };
                builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);
            }
            else
            {
                Console.WriteLine("Reply");
                icmpRLayer =
                    new IcmpEchoReplyLayer
                    {
                        Checksum = null, // Will be filled automatically.
                        Identifier = 456,
                        SequenceNumber = 800,
                    };
                builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpRLayer);
            }


            return builder.Build(DateTime.Now);
        }

    }


}



/*
                
                for (int i = 0; i < allDevices.Count; i++)
                {
                    if (lists[i][0] == null && mac!="Broadcast")
                    {
                        lists[i][0] = mac;
                        lists[i][1] = packet.Ethernet.Source.ToString();
                    }
                    else
                    {
                        if(lists[i][0]==mac )
                        {
                            
                        }
                    }
                    
                }
                
                 if (packet.IpV4.Icmp != null)
            {
                string mac = packet.Ethernet.Source.ToString();
            }
               */