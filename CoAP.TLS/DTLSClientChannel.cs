using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

using System.Net;
using System.Net.Sockets;
using Com.AugustCellars.CoAP.Channel;
using Com.AugustCellars.CoAP.Net;
using Com.AugustCellars.CoAP.TLS;
using Org.BouncyCastle.Crypto.Tls;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.CoAP.TLS
{
    public class DTLSClientChannel : IChannel
    {
        private System.Net.EndPoint _localEP;
        private Int32 _receiveBufferSize;
        private Int32 _sendBufferSize;
        private Int32 _receivePacketSize;
        private int _port;
        private UDPChannel _udpChannel;
        private OneKey _userKey;

        public DTLSClientChannel(OneKey userKey) : this(userKey, 0)
        {
        }

        public DTLSClientChannel(OneKey userKey, Int32 port)
        {
            _port = port;
            _userKey = userKey;
        }

        public DTLSClientChannel(OneKey userKey, System.Net.EndPoint ep)
        {
            _localEP = ep;
            _userKey = userKey;
        }

        /// <inheritdoc/>
        public event EventHandler<DataReceivedEventArgs> DataReceived;

        /// <inheritdoc/>
        public System.Net.EndPoint LocalEndPoint {
            get { return _udpChannel == null ? (_localEP ?? new IPEndPoint(IPAddress.IPv6Any, _port)) : _udpChannel.LocalEndPoint; }
        }

        /// <summary>
        /// Gets or sets the <see cref="Socket.ReceiveBufferSize"/>.
        /// </summary>
        public Int32 ReceiveBufferSize {
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

        private Int32 _running;

        public void Start()
        {
            if (System.Threading.Interlocked.CompareExchange(ref _running, 1, 0) > 0) {
                return;
            }

            if (_udpChannel == null) {


                if (_localEP != null) {
                    _udpChannel = new UDPChannel(_localEP);
                }
                else {
                    _udpChannel = new UDPChannel(_port);

                }
            }

            _udpChannel.DataReceived += ReceiveData;

            _udpChannel.Start();            
        }

        public void Stop()
        {
            lock (_sessionList) {
                foreach (DTLSSession session in _sessionList) {
                    session.Stop();
                }
                _sessionList.Clear();
            }
            _udpChannel.Stop();
        }

        public void Dispose()
        {
            _udpChannel.Dispose();
        }

        public void Send(byte[] data, System.Net.EndPoint ep)
        {
            //  Wrong code but let's get started

            try {
                IPEndPoint ipEP = (IPEndPoint) ep;

                DTLSSession session = FindSession(ipEP);
                if (session == null) {

                    session = new DTLSSession(ipEP, DataReceived, _userKey);
                    AddSession(session);
                    session.Connect(_udpChannel);

                    //   new Thread(() => StreamListener(session)).Start();

                }
                session.Queue.Enqueue(new QueueItem(null, data));
                session.WriteData();

            }
            catch (Exception e) {
                Console.WriteLine("Error in DTLSClientChannel Sending - " + e.ToString());
            }
        }

        private void ReceiveData(Object sender, DataReceivedEventArgs e)
        {
            lock (_sessionList) {
                foreach (DTLSSession session in _sessionList) {
                    if (e.EndPoint.Equals(session.EndPoint)) {
                        session.ReceiveData(sender, e);

                        return;
                    }
                }
            }
        }



        private static List<DTLSSession> _sessionList = new List<DTLSSession>();
        private static void AddSession(DTLSSession session)
        {
            lock (_sessionList) {
                _sessionList.Add(session);
            }
        }

        private static DTLSSession FindSession(IPEndPoint ipEP)
        {
            lock (_sessionList) {

                foreach (DTLSSession session in _sessionList) {
                    if (session.EndPoint.Equals(ipEP))
                        return session;
                }
            }
            return null;
        }
    }
}
