﻿using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Com.AugustCellars.CoAP.Channel;

namespace Com.AugustCellars.CoAP.TLS
{
    /// <summary>
    /// Implement TLS as a channel for the CoAP protocol
    /// </summary>
    public class TcpChannel : IChannel
    {
        private System.Net.EndPoint _localEP;
        private Int32 _port;
        private Int32 _receiveBufferSize;
        private Int32 _receivePacketSize;
        private Int32 _running;
        private Int32 _sendBufferSize;
        private TcpListener _listener;

        /// <inheritdoc/>
        public event EventHandler<DataReceivedEventArgs> DataReceived;

 
        /// <summary>
        /// Initialize a TCP channel with a random port.
        /// </summary>
        public TcpChannel() : this(0)
        { }

        /// <summary>
        /// Initialize a TCP Channel with the specific endpoint port.
        /// </summary>
        /// <param name="port"></param>
        public TcpChannel(Int32 port)
        {
            _port = port;
        }

        /// <summary>
        /// Initialize a TCP channel with an endpoint
        /// </summary>
        /// <param name="localEP"></param>
        public TcpChannel(System.Net.EndPoint localEP)
        {
            _localEP = localEP;
        }

        /// <inheritdoc/>
        public System.Net.EndPoint LocalEndPoint
        {
            get { return _listener == null ? (_localEP ?? new IPEndPoint(IPAddress.IPv6Any, _port)) : _listener.LocalEndpoint; }
        }

        /// <summary>
        /// Gets or sets the <see cref="Socket.ReceiveBufferSize"/>.
        /// </summary>
        public Int32 ReceiveBufferSize
        {
            get { return _receiveBufferSize; }
            set { _receiveBufferSize = value; }
        }

        /// <summary>
        /// Gets or sets the <see cref="Socket.SendBufferSize"/>.
        /// </summary>
        public Int32 SendBufferSize {
            get { return _sendBufferSize; }
            set { _sendBufferSize = value; }
        }

        /// <summary>
        /// Gets or sets the size of buffer for receiving packet.
        /// The default value is <see cref="DefaultReceivePacketSize"/>.
        /// </summary>
        public Int32 ReceivePacketSize {
            get { return _receivePacketSize; }
            set { _receivePacketSize = value; }
        }

        /// <inheritdoc/>
        public void Start()
        {
            if (System.Threading.Interlocked.CompareExchange(ref _running, 1, 0) > 0) {
                return;
            }


            if (_localEP != null) {
                IPEndPoint ipep = (IPEndPoint) _localEP;

                _listener = new TcpListener(ipep.Address, ipep.Port);
                return;
            }
            else {
                _listener = new TcpListener(IPAddress.IPv6Any, _port);
                _listener.Server.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, 0);

            }

            try {
                _listener.Start();

            }
            catch (Exception) {
                throw new Exception("Failed to start TCP connection");
            }

            _localEP = _listener.LocalEndpoint;

            new Thread(() => StartListen2()).Start();
        }

        /// <inheritdoc/>>
        public void Stop()
        {
            if (System.Threading.Interlocked.Exchange(ref _running, 0) == 0) {
                return;
            }

            if (_listener != null) {
                _listener.Stop();
                _listener = null;
            }
        }

        /// <inheritdoc/>
        public void Send(byte[] data, System.Net.EndPoint ep)
        {
            //  Wrong code but let's get started

            try {
                IPEndPoint ipEP = (IPEndPoint) ep;

                TcpSession session = FindSession(ipEP);
                if (session == null) {

                    session = new TcpSession(ipEP, new QueueItem(null, data));
                    session.Connect();
                    AddSession(session);

                    new Thread(() => StreamListener(session)).Start();

                }
                else {
                    session.Queue.Enqueue(new QueueItem(session, data));
                    session.WriteData();
                }

            }
            catch (Exception e) {
                Console.WriteLine("Error in TCP Sending - " + e.ToString());
            }

        }

        /// <inheritdoc/>
        public void Dispose()
        {
            Stop();
        }

        private void StartListen2()
        {

            try {
                while (true) {
                    // Program blocks on Accept() until a client connects

                    TcpClient soTcp = _listener.AcceptTcpClient();
                                     
                    TcpSession session = new TcpSession(soTcp);

                    new Thread(() => StreamListener(session)).Start();

                    AddSession(session);

                }
            }
            catch (Exception) {
                ;
            }

        }

        private void NewTcpClient(TcpClient soTcp)
        {

        }

        private static List<TcpSession> _sessionList = new List<TcpSession>();
        private static void AddSession(TcpSession session)
        {
            lock (_sessionList) {
                _sessionList.Add(session);
            }
        }

        private static TcpSession FindSession(IPEndPoint ipEP)
        {
            lock (_sessionList) {

                foreach (TcpSession session in _sessionList) {
                    if (session.EndPoint.Equals(ipEP))
                        return session;
                }
            }
            return null;
        }

        private void StreamListener(TcpSession soTcp)
        {
            try {

                NetworkStream stream = soTcp.Stream;

                byte[] bytes = new byte[1163];
                int offset = 0;
                int messageSize;

                //  Start by sending the capability message
                byte[] data = { 0x10, 0xE1, 0x04 };
                stream.Write(data, 0, data.Length);

                while (true) {
                    int i = stream.Read(bytes, offset, bytes.Length-offset);
                    i += offset;

                    while (i > 0) {
                        //  Do I have a full record?

                        int dataSize = (bytes[0] >> 4) & 0xf;
                        switch (dataSize) {
                            case 13:
                                messageSize = bytes[1] + 13 + 3;
                                break;

                            case 14:
                                messageSize = (bytes[1] * 256 + bytes[2]) + 269 + 4;
                                break;

                            case 15:
                                messageSize = ((bytes[1] * 256 + bytes[2]) * 256 + bytes[3]) * 256 + bytes[4] + 65805 + 6;
                                break;

                            default:
                                messageSize = dataSize + 2;
                                break;
                        }
                        messageSize += (bytes[0] & 0xf); // Add token buffer

                        if (i >= messageSize) {
                            byte[] message = new byte[messageSize];
                            Array.Copy(bytes, message, messageSize);
                            Array.Copy(bytes, messageSize, bytes, 0, i - messageSize);
                            offset = i - messageSize;
                            i -= messageSize;

                            FireDataReceived(message, soTcp.EndPoint);
                        }
                        else {
                            break;
                        }
                    }
                }

            }
            catch (Exception  e) {
                Console.WriteLine("StreamListener --> " + e.ToString());
            }
        }

        private void FireDataReceived(Byte[] data, System.Net.EndPoint ep)
        {
            EventHandler<DataReceivedEventArgs> h = DataReceived;
            if (h != null) {
                h(this, new DataReceivedEventArgs(data, ep));
            }
        }

    }
}
