using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;

using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Net.Security;
using System.Security.Authentication;

/*

The MIT License (MIT)

Copyright © 2018 - Dennis "MazyModz" Andersson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

namespace SslSockets
{
    public enum LogType 
    {
        Default,
        Warning,
        Error
    }
    public interface IValidatable 
    {
        /// <returns>'true' if the object is valid</returns>
        bool IsValid();
    }

    public class ClientConnectedEventArgs<TClient> : EventArgs where TClient: SslServerClient, new()
    {
        public TClient Client { get; }
        public ClientConnectedEventArgs(TClient client)
        {
            Client = client;
        }
    }
    public class ClientDisconnectedEventArgs<TClient> : ClientConnectedEventArgs<TClient> where TClient: SslServerClient, new()
    {
        public ClientDisconnectedEventArgs(TClient client) : base(client)
        {
        }
    }
    public class MessageReceivedEventArgs<TClient> : EventArgs where TClient: SslServerClient, new()
    {
        public TClient Client { get; }
        public string Message { get; }
        public MessageReceivedEventArgs(TClient client, string message)
        {
            Client = client;
            Message = message;
        }
    }

    public class SslServerClient : IValidatable, IDisposable
    {
        /// <summary>
        /// The SSL stream where the communication between the server is handled
        /// </summary>
        public SslStream Stream { get; }

        /// <summary>
        /// The TCP client that is connected to the server
        /// </summary>
        public TcpClient Client { get; }

        /// <summary>
        /// Initializes a new instance of a client connected in a ssl server
        /// </summary>
        /// <param name="stream">The SSL stream that is used by this client and server</param>
        /// <param name="client">The TCP client that is connected to the server</param>
        public SslServerClient(SslStream stream, TcpClient client)
        {
            Stream = stream;
            Client = client;
        }

        public SslServerClient()
        {
        }

        public virtual bool IsValid()
        {
            return Stream != null && Client != null;
        }
        public virtual void Dispose()
        {
            Stream.Dispose();
            Client.Close();
        }
    }
    public struct SslServerClientData
    {
        public TcpClient Client { get; }
        public SslStream Stream { get; }
        public SslServerClientData(TcpClient client, SslStream stream)
        {
            Client = client;
            Stream = stream;
        }
    }

    public abstract class SslServer<TClient> : IDisposable, IValidatable where TClient: SslServerClient, new()
    {
        #region Fields
        private X509Certificate2 _serverCertificate;
        private bool _bIsClientCertificateRequired;
        private SslProtocols _sslProtocol;
        private bool _bCheckCertificateRevocation;

        private TcpListener _listener;

        /// <summary>
        /// Byte array to store the first packet of one byte
        /// </summary>
        private byte[] _firstBuffer = new byte[1];

        /// <summary>
        /// Byte array to store the second packet
        /// </summary>
        private byte[] _secondBuffer = new byte[1024];

        /// <summary>
        /// If the first packet has been received and we are waiting to receive the second one
        /// </summary>
        private bool _bIsWaitingForSecondPacket;

        /// <summary>
        /// if we are in the proccess of receiving the second packet
        /// </summary>
        private bool _bIsReceivingSecondPacket;
        #endregion

        #region Properties
        /// <summary>
        /// The clients that are connected to the server
        /// </summary>
        public List<TClient> Clients { get; set; }
        public TcpListener Listener
        {
            get { return _listener; }
        }
        #endregion

        #region Events
        /// <summary>
        /// When a new client connected to the server
        /// </summary>
        public EventHandler<ClientConnectedEventArgs<TClient>> ClientConnected;

        /// <summary>
        /// When a connected client disconnected
        /// </summary>
        public EventHandler<ClientDisconnectedEventArgs<TClient>> ClientDisconnected;

        /// <summary>
        /// When a message was received from a connected client
        /// </summary>
        public EventHandler<MessageReceivedEventArgs<TClient>> MessageReceived;
        #endregion

        public SslServer(X509Certificate2 certificate, bool bClientRequiredCertificate = false, SslProtocols sslProtocol = SslProtocols.Tls, bool bCheckCertificateRevocation = false)
        {
            _serverCertificate = certificate;
            _bIsClientCertificateRequired = bClientRequiredCertificate;
            _sslProtocol = sslProtocol;
            _bCheckCertificateRevocation = bCheckCertificateRevocation;

            Clients = new List<TClient>();
        }

        /// <summary>
        /// Starts to listen for incomming connections
        /// </summary>
        /// <param name="endPoint">The endpoint to listen on</param>
        public void Listen(IPEndPoint endPoint)
        {
            _listener = new TcpListener(endPoint);
            _listener.Start();
            _listener.BeginAcceptTcpClient(AcceptCallback, _listener);
        }

        /// <summary>
        /// Writes a message to the given client
        /// </summary>
        /// <param name="message">The message to send</param>
        /// <param name="client">The client to send the message to</param>
        public void Write(string message, TClient client)
        {
            try
            {
                byte[] data = Encoding.ASCII.GetBytes(message);
                client.Stream.BeginWrite(data, 0, data.Length, WriteCallback, client);
            }
            catch (Exception ex)
            {
                Log($"Exeption [SslServer::Write]:\n{ ex.Message }", LogType.Error);
            }
        }

        /// <summary>
        /// Writes a message to the given tcpclient
        /// </summary>
        /// <param name="message">The message to send</param>
        /// <param name="tcpClient">The client to send the message to</param>
        public void Write(string message, TcpClient tcpClient)
        {
            Write(message, Clients.Find(x => x.Client == tcpClient));
        }

        /// <summary>
        /// Writes a message to the given ssl stream
        /// </summary>
        /// <param name="message">The message to send</param>
        /// <param name="stream">The stream to send the message to</param>
        public void Write(string message, SslStream stream)
        {
            Write(message, Clients.Find(x => x.Stream == stream));
        }

        #region AsyncCallbacks
        protected virtual void AcceptCallback(IAsyncResult ar)
        {
            try
            {
                // Begin listening for another connection
                _listener.BeginAcceptTcpClient(AcceptCallback, ar.AsyncState);

                TcpClient tcpClient = _listener.EndAcceptTcpClient(ar);

                // Initialize a ssl stream and authenticate the server and optionally the client
                SslStream ssl = new SslStream(tcpClient.GetStream(), false, ClientCertificateValidationCallback);
                ssl.BeginAuthenticateAsServer(_serverCertificate, _bIsClientCertificateRequired, _sslProtocol, _bCheckCertificateRevocation, 
                    ServerAuthenticateCallback, new SslServerClientData(tcpClient, ssl));
            }
            catch (Exception ex)
            {
                Log($"Exeption [SslServer::ConnectCallback]:\n{ ex.Message }", LogType.Error);
            }
        }
        protected virtual void ReadCallback(IAsyncResult ar)
        {
            TClient client = ar.AsyncState as TClient;
            SslStream ssl = client.Stream;

            try
            {
                // Convert the byte array to a string 
                int received = ssl.EndRead(ar);
                if (received > 0)
                {
                    if (_bIsWaitingForSecondPacket && _bIsReceivingSecondPacket)
                    {
                        _bIsWaitingForSecondPacket = false;
                        _bIsReceivingSecondPacket = false;

                        StringBuilder sb = new StringBuilder();
                        Decoder decoder = Encoding.UTF8.GetDecoder();

                        char[] first = new char[decoder.GetCharCount(_firstBuffer, 0, 1)];
                        decoder.GetChars(_firstBuffer, 0, 1, first, 0);

                        char[] second = new char[decoder.GetCharCount(_secondBuffer, 0, received)];
                        decoder.GetChars(_secondBuffer, 0, received, second, 0);

                        sb.Append(first);
                        sb.Append(second);

                        string message = sb.ToString();
                        MessageReceived?.Invoke(this, new MessageReceivedEventArgs<TClient>(client, message));
                    }

                    BeginRead(ssl, client);
                }
            }
            catch
            {
                DisconnectClient(client);
            }
        }
        protected virtual void WriteCallback(IAsyncResult ar)
        {
            if((ar.AsyncState as TClient).Stream is var stream)
                stream.EndWrite(ar);
        }
        protected virtual void ServerAuthenticateCallback(IAsyncResult ar)
        {
            if ((ar.AsyncState is SslServerClientData data))
            {
                try
                {
                    data.Stream.EndAuthenticateAsServer(ar);

                    TClient client = AddClient(data.Stream, data.Client);
                    BeginRead(data.Stream, client);
                }
                catch
                {
                    data.Stream.Dispose();
                    data.Client.Dispose();
                }
            }
        }
        #endregion

        /// <summary>
        /// Begins to read of the ssl stream of the client
        /// </summary>
        /// <param name="ssl">The ssl stream to read on</param>
        /// <param name="client">The client to read on</param>
        protected void BeginRead(SslStream ssl, TClient client)
        {
            try
            {
                if (_bIsWaitingForSecondPacket)
                {
                    // Receive the second packet
                    _bIsReceivingSecondPacket = true;
                    ssl.BeginRead(_secondBuffer, 0, _secondBuffer.Length, ReadCallback, client);
                }
                else
                {
                    // Receive the first packet
                    _bIsWaitingForSecondPacket = true;
                    _bIsReceivingSecondPacket = false;

                    ssl.BeginRead(_firstBuffer, 0, 1, ReadCallback, client);
                }
            }
            catch
            {
                // If it failed in this catch block it means the client disconnected
                DisconnectClient(client);
            }
        }

        /// <summary>
        /// Disconnect process for a client
        /// </summary>
        /// <param name="client">The client to handle</param>
        protected void DisconnectClient(TClient client)
        {
            ClientDisconnected?.Invoke(this, new ClientDisconnectedEventArgs<TClient>(client));
            Clients.Remove(client);
            client.Dispose();
        }

        #region Virtual and Abstract Members
        /// <summary>
        /// Called when a client should be added to the server
        /// </summary>
        /// <param name="ssl">The ssl stream of the client to add</param>
        /// <param name="tcpClient">The tcp client of the client to add</param>
        /// <returns></returns>
        protected virtual TClient AddClient(SslStream ssl, TcpClient tcpClient)
        {
            TClient client = CreateClient(tcpClient, ssl);
            Clients.Add(client);

            ClientConnected?.Invoke(this, new ClientConnectedEventArgs<TClient>(client));

            return client;
        }
        /// <summary>
        /// Initializes a new instance of a client to connect to the server
        /// </summary>
        /// <param name="tcpClient">The tcpclient of the client</param>
        /// <param name="stream">The ssl stream of the client</param>
        /// <returns></returns>
        protected abstract TClient CreateClient(TcpClient tcpClient, SslStream stream);
        /// <summary>
        /// Prints a log message
        /// </summary>
        /// <param name="logMessage">Message to print</param>
        /// <param name="type">The type of error</param>
        protected virtual void Log(string logMessage, LogType type)
        {
            Console.WriteLine($"[{type.ToString()}] {logMessage}");
        }
        /// <summary>
        /// When a client certificate is validated
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="certificate"></param>
        /// <param name="chain"></param>
        /// <param name="sslPolicyErrors"></param>
        /// <returns></returns>
        protected virtual bool ClientCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
        #endregion   

        #region Interface Implementations
        public void Dispose()
        {
            _listener.Stop();

            Clients.ForEach(x => x.Dispose());
            Clients.Clear();
        }
        public bool IsValid()
        {
            return true;
        }
        #endregion
    }
}
