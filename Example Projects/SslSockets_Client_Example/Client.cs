using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Net.Security;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;

namespace SslSockets
{
    public enum DisconnectType
    {
        UserForced = 0,
        ConnectionClosed,
        ConnectionFailed
    }

    public class DisconnectedEventArgs : EventArgs
    {
        public DisconnectType DisconnectReason { get; }
        public DisconnectedEventArgs(DisconnectType disconnectReason)
        {
            DisconnectReason = disconnectReason;
        }
    }
    public class MessageReceivedEventArgs : EventArgs
    {
        public string Message { get; }
        public MessageReceivedEventArgs(string message)
        {
            Message = message;
        }
    }

    public class SslClient : IDisposable
    {
        #region Fields
        private TcpClient _client;
        private IPEndPoint _endPoint;

        private SslStream _ssl;
        private string _serverName;

        private byte[] _firstBuffer = new byte[1];
        private byte[] _secondBuffer = new byte[1024];

        private bool _bIsWaitingForSecondPacket;
        private bool _bIsRecevingSecondPacket;
        #endregion

        #region Properties
        public TcpClient Client
        {
            get { return _client; }
        }
        #endregion

        #region Events
        /// <summary>
        /// When a message was received from the server
        /// </summary>
        public EventHandler<MessageReceivedEventArgs> MessageReceived;

        /// <summary>
        /// When this client was disconnected from the server
        /// </summary>
        public EventHandler<DisconnectedEventArgs> Disconnected;

        /// <summary>
        /// When this client connected to a server
        /// </summary>
        public EventHandler Connected;
        #endregion

        /// <summary>
        /// Initializes a new instance of a SslClient that can connect to a SslServer
        /// </summary>
        public SslClient() {  }
        
        /// <summary>
        /// Connects to a ssl server at the endpoint and servername
        /// </summary>
        /// <param name="endPoint">The endpoint to connect to</param>
        /// <param name="serverName">The target host name</param>
        public void Connect(IPEndPoint endPoint, string serverName = null)
        {
            _endPoint = endPoint;
            _serverName = serverName;

            _client = new TcpClient(AddressFamily.InterNetwork);
            _client.BeginConnect(endPoint.Address, endPoint.Port, ConnectCallback, _client);
        }

        /// <summary>
        /// Sends a message to the SSL stream connected to the server
        /// </summary>
        /// <param name="message">The message to send to the stream</param>
        public void Write(string message)
        {
            try
            {
                byte[] data = Encoding.ASCII.GetBytes(message);
                _ssl.BeginWrite(data, 0, data.Length, WriteCallback, _ssl);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Exeption [Client::Write]:\n{ ex.Message }");
            }
        }

        #region AsyncResult Callbacks
        protected virtual void ConnectCallback(IAsyncResult ar)
        {
            try
            {
                _client.EndConnect(ar);
                _ssl = new SslStream(_client.GetStream(), false, CertificateValidationCallback);
                _ssl.BeginAuthenticateAsClient(_serverName, AuthenticateCallback, _ssl);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Exeption [Client::ConnectCallback]:\n{ ex.Message }");
            }
        }
        protected virtual void ReadCallback(IAsyncResult ar)
        {
            try
            {
                int received = _ssl.EndRead(ar);
                if (received > 0)
                {
                    if(_bIsWaitingForSecondPacket && _bIsRecevingSecondPacket)
                    {
                        _bIsWaitingForSecondPacket = false;
                        _bIsRecevingSecondPacket = false;

                        StringBuilder sb = new StringBuilder();
                        Decoder decoder = Encoding.UTF8.GetDecoder();

                        char[] first = new char[decoder.GetCharCount(_firstBuffer, 0, 1)];
                        decoder.GetChars(_firstBuffer, 0, 1, first, 0);

                        char[] second = new char[decoder.GetCharCount(_secondBuffer, 0, received)];
                        decoder.GetChars(_secondBuffer, 0, received, second, 0);

                        sb.Append(first);
                        sb.Append(second);

                        string message = sb.ToString();
                        MessageReceived?.Invoke(this, new MessageReceivedEventArgs(message));
                    }

                    BeginRead();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Exeption [Client::ReadCallback]:\n{ ex.Message }");
            }
        }
        protected virtual void AuthenticateCallback(IAsyncResult ar)
        {
            var ssl = ar.AsyncState as SslStream;
            try
            {
                ssl.EndAuthenticateAsClient(ar);

                Connected?.Invoke(this, new EventArgs());
                BeginRead();
            }
            catch
            {
                ssl.Dispose();
            }
        }
        protected virtual void WriteCallback(IAsyncResult ar)
        {
            _ssl.EndWrite(ar);
        }
        #endregion

        /// <summary>
        /// Begin Async reading from SSL stream for incomming messages
        /// </summary>
        protected void BeginRead()
        {
            try
            {
                if (_bIsWaitingForSecondPacket)
                {
                    _bIsRecevingSecondPacket = true;
                    _ssl.BeginRead(_secondBuffer, 0, _secondBuffer.Length, ReadCallback, _ssl);
                }
                else
                {
                    _bIsWaitingForSecondPacket = true;
                    _bIsRecevingSecondPacket = false;

                    _ssl.BeginRead(_firstBuffer, 0, 1, ReadCallback, _ssl);
                }
            }
            catch
            {
                // If reading failed here then the connection must have been closed
                Disconnected?.Invoke(this, new DisconnectedEventArgs(DisconnectType.ConnectionClosed));

                _client.Close();
                _ssl.Dispose();
            }
        }

        protected virtual bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateNameMismatch;
        }

        public void Dispose()
        {
            _client.Close();
            _ssl.Dispose();
        }
    }
}
