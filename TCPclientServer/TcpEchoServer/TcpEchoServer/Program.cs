using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;

namespace TcpEchoServer
{
    class Program
    {
        private const int BUFSIZE = 32; // Size of received buffer

        static void Main(string[] args)
        {
            int serverPort = 7;
            TcpListener listener = null;
            try
            {
                // create a TcpListener to accept client connections
                listener = new TcpListener(IPAddress.Any, serverPort);
                listener.Start();
            }
            catch(SocketException se)
            {
                Console.WriteLine(se.ErrorCode + ": " + se.Message);
                Environment.Exit(se.ErrorCode);
            }

            byte[] receiveBuffer = new Byte[BUFSIZE]; // receive buffer
            int bytesReceived;                         // receive byte count

            for (; ; ) //run forever, accepting and servicing connections
            {
                TcpClient client = null;
                NetworkStream netStream = null;

                try
                {
                    client = listener.AcceptTcpClient(); // get client connections
                    netStream = client.GetStream();
                    Console.Write("handling client - ");

                    //Receive untill client closes connection, indicated by 0 return value
                    int totalBytesEchoed = 0;

                    while ((bytesReceived = netStream.Read(receiveBuffer, 0, receiveBuffer.Length)) > 0)
                    {
                        netStream.Write(receiveBuffer, 0, bytesReceived);
                        totalBytesEchoed += bytesReceived;
                    }

                    Console.WriteLine("echoed {0} bytes", totalBytesEchoed);

                    //Close the stream and socket. we are done with this client.
                    netStream.Close();
                    client.Close();
                }
                catch(Exception e)
                {
                    Console.WriteLine(e.Message);
                    netStream.Close();
                }
            }

           

        }
    }
}
