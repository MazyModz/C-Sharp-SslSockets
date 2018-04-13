using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using SslSockets;

namespace SslSockets_Client_Example
{
    class Program
    {
        private static bool _bIsConnected = false;
        static void Main(string[] args)
        {
            SslClient client = new SslClient();

            // Bind the client events
            client.Connected += OnConnected;
            client.Disconnected += OnDisconnected;
            client.MessageReceived += OnMessageReceived;

            // Connect to the endpoint and the matching server certificate subject name
            client.Connect(new IPEndPoint(IPAddress.Parse("127.0.0.1"), 80), "MyServerCertificateCN");

            while(true)
            {
                if (_bIsConnected)
                {
                    Console.Clear();
                    Console.WriteLine("Enter a message to the server:");

                    string input = Console.ReadLine();

                    if (input.ToLower() == "exit" || input.ToLower() == "quit")
                    {
                        Environment.Exit(0);
                    }
                    else
                    {
                        client.Write(input);
                    }
                }
                else
                {
                    Console.Clear();
                    Console.WriteLine("Waiting for connection. . .");
                }
            }
        }

        private static void OnConnected(object s, EventArgs e)
        {
            _bIsConnected = true;
        }

        private static void OnDisconnected(object s, DisconnectedEventArgs e)
        {
            Console.WriteLine("Disconnected from the server.");
            _bIsConnected = false;
        }

        private static void OnMessageReceived(object s, MessageReceivedEventArgs e)
        {
            Console.WriteLine($"Server: { e.Message }");
        }
    }
}
