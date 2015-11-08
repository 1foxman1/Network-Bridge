using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net.Sockets;

namespace TcpEchoClient
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Insert input:");

            string echoString = Console.ReadLine(); // get input
            byte[] byteBuffer = Encoding.ASCII.GetBytes(echoString); //encode string

            string serverIP = "172.16.1.1";
            int serverPort = 7;

            TcpClient client = null;
            NetworkStream netStream = null;
            try
            {

                client = new TcpClient(serverIP, serverPort);

                Console.WriteLine("Connected to server... sending echo stream");

                netStream = client.GetStream();

                netStream.Write(byteBuffer, 0, byteBuffer.Length); //send encoded string to server

                Console.WriteLine("sent {0} bytes to server...", byteBuffer.Length);

                int totalBytesReceieved = 0; //total bytes received
                int bytesReceived = 0; //bytes received in last read

                // Receive the same string back from the server
                while (totalBytesReceieved < byteBuffer.Length)
                {
                    if ((bytesReceived = netStream.Read(byteBuffer, totalBytesReceieved, byteBuffer.Length - totalBytesReceieved)) == 0)
                    {
                        Console.WriteLine("Connection closed  prematurely.");
                        break;
                    }
                    totalBytesReceieved += bytesReceived;
                }

                Console.WriteLine("Received {0} bytes from server: {1}", totalBytesReceieved, Encoding.ASCII.GetString(byteBuffer, 0, totalBytesReceieved));
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                netStream.Close();
                client.Close();
            }

            Console.ReadKey();

        }
    }
}
