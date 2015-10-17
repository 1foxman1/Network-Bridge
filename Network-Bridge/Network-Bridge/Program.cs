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

                    //Console.WriteLine("HARA: " + packet.Ethernet.Arp.TargetProtocolIpV4Address.ToString());

                    string SrcMac = CheckAddress(packet);
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

                   //SendResponse(pySrc, pyDest, ipDest, ipSrc);
                }
                else//packet type is icmp
                {
                    Console.WriteLine("ICMP Packet: " + packet.Length);
                    MyDevice newDev = null;

                    foreach (MyDevice dev in myDevices)
                    {
                        if (dev.ID == threadID)
                        {
                            newDev = dev;
                        }
                    }

                    Address addr = null;
                    foreach (Address address in newDev.Addresses)
                    {
                        if (address.Ip.Equals(packet.Ethernet.IpV4.Destination))
                        {
                            addr = address;
                        }
                    }

                    EthernetLayer ethLayer = packet.Ethernet.Payload.ExtractLayer() as EthernetLayer;
                    MacAddress ma = new MacAddress(addr.Mac);
                    //ethLayer.Destination = ma;
                    IpV4Layer ipLayer = (IpV4Layer)packet.Ethernet.IpV4.ExtractLayer();
                    PayloadLayer payload = (PayloadLayer)packet.Ethernet.Payload.ExtractLayer();

                    //Console.WriteLine("ETHER LAYER DESTINATION: " + ethLayer.Destination);
                    //Packet newPacket = PacketBuilder.Build(DateTime.Now, ethLayer, ipLayer, payload);

                    //newDev.Communicator.SendPacket(newPacket);
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

        private static string CheckAddress(Packet packet)
        {
            int threadID = System.Threading.Thread.CurrentThread.ManagedThreadId; //fetch current thread ID
            string mac = packet.Ethernet.Source.ToString();
            string ip = packet.Ethernet.IpV4.Source.ToString();

            MyDevice md;
            foreach (MyDevice device in myDevices) //checks if it's a new device or if a mac should be added
            {
                // Console.WriteLine(device.ID);
                if (device.ID == threadID) //found device
                {
                    bool inList = false;
                    md = device;
                    
                    foreach(Address address in device.Addresses)
                    {
                        if (address.Mac.Equals(mac))
                        {
                            inList = true;
                        }
                    }

                    if (!inList)
                    {
                        //Console.WriteLine("Device Address: " + device.Address);
                        device.Addresses.Add(new Address(ip,mac)); // if device mac not in list, adds it
                        Console.WriteLine("Mac address: " + mac + " added from device: " + device.ID);
                    }
                }

                
            }

            return mac;

            //if(md!=null)
            //{
            //    var etherPacket = new PacketDotNet.EthernetPacket(md.,mac,);
            //    var arppacket = new PacketDotNet.ARPPacket(PacketDotNet.ARPOperation.Response, );
            //    etherPacket.PayloadPacket = arppacket;

            //}
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