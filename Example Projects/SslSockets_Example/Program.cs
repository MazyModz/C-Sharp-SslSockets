using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using SslSockets;
using System.Security.Cryptography.X509Certificates;

// Object stored on the server for a client thats connected
public class MySslSocketServerClient : SslServerClient
{
    public Guid GUID { get; }
    public MySslSocketServerClient(SslStream stream, TcpClient client, Guid guid) : base(stream, client)
    {
        GUID = guid;
    }
    public MySslSocketServerClient() { }
}

// Custom server object using a custom server client
public class MySslSocketServer : SslServer<MySslSocketServerClient>
{
    public MySslSocketServer(X509Certificate2 certificate) : base(certificate)
    {
    }

    /// <summary>
    /// Broadcast a message to all connected clients
    /// </summary>
    /// <param name="message">The message to send</param>
    public void Broadcast(string message)
    {
        Clients.ForEach(x => Write(message, x));
    }

    protected override MySslSocketServerClient CreateClient(TcpClient tcpClient, SslStream stream)
    {
        // Create my connected custom client data
        return new MySslSocketServerClient(stream, tcpClient, Guid.NewGuid());
    }
}

namespace SslSockets_Server_Example
{
    class Program
    {
        static void Main(string[] args)
        {
            if (GetCertificate("MyCertificateCN") is X509Certificate2 certificate)
            {
                MySslSocketServer server = new MySslSocketServer(certificate);

                // Bind the events on the server objects
                server.ClientConnected += OnClientConnected;
                server.ClientDisconnected += OnClientDiconnected;
                server.MessageReceived += OnMessageReceived;

                // Listen on the given endpoint
                server.Listen(new IPEndPoint(IPAddress.Parse("127.0.0.1"), 80));

                while (true)
                {
                    Console.WriteLine("Server started listening");
                    Console.WriteLine($"Certificate Name: { certificate.SubjectName }");
                    Console.WriteLine("Enter a message to broadcast to all clients | or 'exit' or 'quit' to stop the server ");

                    string input = Console.ReadLine();
                    if (input.ToLower() == "exit" || input.ToLower() == "quit")
                    {
                        Environment.Exit(0);
                    }
                    else
                    {
                        server.Broadcast(input);
                        Console.Clear();
                    }
                }
            }
        }

        private static X509Certificate2 GetCertificate(string subjectName)
        {
            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2 cert = new X509Certificate2();
            store.Certificates.Add(cert);

            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, false);
            return (certs.Count > 0) ? certs[0] : null;
        }

        private static void OnClientConnected(object s, ClientConnectedEventArgs<MySslSocketServerClient> e)
        {
            Console.WriteLine($"{ e.Client.GUID } connected");
        }

        private static void OnClientDiconnected(object s, ClientDisconnectedEventArgs<MySslSocketServerClient> e)
        {
            Console.WriteLine($"{ e.Client.GUID } disconnected");
        }

        private static void OnMessageReceived(object s, MessageReceivedEventArgs<MySslSocketServerClient> e)
        {
            Console.WriteLine($"[{ e.Client.GUID }]: { e.Message }");
        }
    }
}
