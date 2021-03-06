# C-Sharp-SslSockets (C# SslSockets)
A Client and Server Socket Library with SSL Encryption. Provides an easy and fast way of creating flexible Client and Server applications.

The library is contained within two files;
 - Client.cs (SslSockets.SslClient)
 - Server.cs (SslSockets.SslServer)

## SslServer (Server.cs)
This is the object used to create a listen server application. This object is marked as abstract, so you will need to create a new child object and implement the abstract members.

This object is also generic, where the type must be of a _**SslServerClient**_. **_SslServerClients_** are objects used by the server, to store data for each client that is connected to the server.

#### SslServer Implementation Example
First, you will need to create a child object of SslServer.
```c#
// Custom server object using a custom server client
public class MySslSocketServer : SslServer<SslServerClient>
{
    public MySslSocketServer(X509Certificate2 certificate) : base(certificate)
    {
    }
    
    protected override SslServerClient CreateClient(TcpClient tcpClient, SslStream stream)
    {
        // Create my connected custom client data
        return new SslServerClient(stream, tcpClient);
    }
}
```

CreateClient(TcpClient, SslStream) is an abstract member from SslServer and has to be implemented. This should return a new instance of the generic type of the SslServer (TClient).

After you have created a new instance of your SslServer, you can run the server in your application.
```c#
using SslSockets;
static void Main(string[] args)
{
    MySslSocketServer server = new MySslSocketServer(GetCertificate("MyCertificateCN"));

    // Bind the events on the server objects
    server.ClientConnected += OnClientConnected;
    server.ClientDisconnected += OnClientDiconnected;
    server.MessageReceived += OnMessageReceived;

    // Listen on the given endpoint
    server.Listen(new IPEndPoint(IPAddress.Parse("127.0.0.1"), 80));

    Console.WriteLine("Press any key to continue. . .");
    Console.ReadKey(true);
}
```

## SslClient (Client.cs)
This is the object used for creating a client application. Unlike the SslServer this is not marked as abstract, so no child object needs to be created. 

#### SslClient Implementation Example
No child object has to be created, so we can create a new instance in our application. 
```c#
using SslSockets;

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
        if(_bIsConnected)
        {
            Console.Clear();
            Console.WriteLine("Enter a message to the server:");

            // Write a message to the server
            string input = Console.ReadLine();
            client.Write(input);
        }
        else
        {
            Console.Clear();
            Console.WriteLine("Connecting. . .");
        }
    }
}
```
