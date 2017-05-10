using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
using Com.AugustCellars.CoAP.Channel;
using Com.AugustCellars.COSE;

using PeterO.Cbor;

using Org.BouncyCastle;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Security;
using DataReceivedEventArgs = Com.AugustCellars.CoAP.Channel.DataReceivedEventArgs;

namespace Com.AugustCellars.CoAP.TLS
{
    class DTLSSession
    {
        private DtlsClient _client;
        private readonly IPEndPoint _ipEndPoint;
        private DtlsTransport _dtlsClient;
        private readonly OurTransport _transport;
        private OneKey _userKey;
        private KeySet _userKeys;
        private KeySet _serverKeys;

        private readonly ConcurrentQueue<QueueItem> _queue = new ConcurrentQueue<QueueItem>();
        private EventHandler<DataReceivedEventArgs> _dataReceived;


        public DTLSSession(IPEndPoint ipEndPoint, EventHandler<DataReceivedEventArgs> dataReceived, OneKey userKey)
        {
            _ipEndPoint = ipEndPoint;
            _dataReceived = dataReceived;
            _userKey = userKey;
            _transport = new OurTransport(ipEndPoint);
        }

        public DTLSSession(IPEndPoint ipEndPoint, EventHandler<DataReceivedEventArgs> dataReceived, KeySet serverKeys, KeySet userKeys)
        {
            _ipEndPoint = ipEndPoint;
            _dataReceived = dataReceived;
            _userKeys = userKeys;
            _serverKeys = serverKeys;
            _transport = new OurTransport(ipEndPoint);
        }

        /*
        public DTLSSession(TcpClient client)
        {
            _client = client;
            _ipEndPoint = (IPEndPoint) client.Client.RemoteEndPoint;
        }
        */

        public ConcurrentQueue<QueueItem> Queue
        {
            get { return _queue; }
        }

        public IPEndPoint EndPoint
        {
            get { return _ipEndPoint; }
        }

        public void Connect(UDPChannel udpChannel)
        {
            BasicTlsPskIdentity pskIdentity = null;

            if (_userKey != null) {
                if (_userKey.HasKeyType((int) COSE.GeneralValuesInt.KeyType_Octet)) {
                    CBORObject kid = _userKey[COSE.CoseKeyKeys.KeyIdentifier];

                    if (kid != null) {
                        pskIdentity = new BasicTlsPskIdentity(kid.GetByteString(), _userKey[CoseKeyParameterKeys.Octet_k].GetByteString());
                    }
                    else {
                        pskIdentity = new BasicTlsPskIdentity(new byte[0], _userKey[CoseKeyParameterKeys.Octet_k].GetByteString());
                    }
                }   
            }
            _client = new DtlsClient(null, pskIdentity);

            DtlsClientProtocol clientProtocol = new DtlsClientProtocol(new SecureRandom());

//            _transport = new OurTransport(EndPoint);
            _transport.UDPChannel = udpChannel;

            DtlsTransport dtlsClient = clientProtocol.Connect(_client, _transport);
            _dtlsClient = dtlsClient;

            //  We are now in the world of a connected system -
            //  We need to do the receive calls

            new Thread(() => StartListen()).Start();
        }

        public void Accept(UDPChannel udpChannel, byte[] message)
        {
            DtlsServerProtocol serverProtocol = new DtlsServerProtocol(new SecureRandom());

            TlsServer server = new DtlsServer(_serverKeys, _userKeys);
  //          _transport = new OurTransport(udpChannel, EndPoint);
            _transport.UDPChannel = udpChannel;
            _transport.Receive(message);
            
            DtlsTransport dtlsServer = serverProtocol.Accept(server, _transport);


            _dtlsClient = dtlsServer;

            new Thread(() => StartListen()).Start();
  
        }

        public void Stop()
        {
            if (_dtlsClient != null) {
                _dtlsClient.Close();
                _dtlsClient = null;
            }
            _client = null;
        }


        private Int32 _writing;
        private readonly Object _writeLock = new Object();

        public void WriteData()
        {
            if (_queue.Count == 0)
                return;
            lock (_writeLock) {
                if (_writing > 0)
                    return;
                _writing = 1;
            }

            while (Queue.Count > 0) {
                QueueItem q;
                if (!_queue.TryDequeue(out q))
                    break;

                _dtlsClient.Send(q.Data, 0, q.Data.Length);

                q = null;
            }

            lock (_writeLock) {
                _writing = 0;
                if (_queue.Count > 0)
                    WriteData();
            }

            
        }

        public void ReceiveData(Object sender, DataReceivedEventArgs e)
        {
            _transport.Receive(e.Data);
        }

        void StartListen()
        {
            byte[] buf = new byte[2000];
            while (true) {
                int size = _dtlsClient.Receive(buf, 0, buf.Length, -1);
                byte[] buf2 = new byte[size];
                Array.Copy(buf, buf2, size);
                FireDataReceived(buf2, _ipEndPoint);
            }
        }

        private void FireDataReceived(Byte[] data, System.Net.EndPoint ep)
        {
            EventHandler<DataReceivedEventArgs> h = _dataReceived;
            if (h != null)
                h(this, new DataReceivedEventArgs(data, ep));
        }

        class OurTransport : DatagramTransport
        {
            private UDPChannel _udpChannel;
            private System.Net.EndPoint _ep;


            public OurTransport(System.Net.EndPoint ep)
            {
                _ep = ep;
            }

            public UDPChannel UDPChannel
            {
                set { _udpChannel = value; }
            }

            public void Close()
            {
                _udpChannel = null;
            }

            public int GetReceiveLimit()
            {
                return 1100;
                return _udpChannel.ReceiveBufferSize;
            }

            public int GetSendLimit()
            {
                return 1100;
                return _udpChannel.SendBufferSize;
            }

            public int Receive(byte[] buf, int off, int len, int waitMillis)
            {
                lock (_receivingQueue) {
                    if (_receivingQueue.Count < 1) {
                        try {
                          //  Monitor.Wait(_receivingQueue, waitMillis);
                            Monitor.Wait(_receivingQueue);
                        }
                        catch (ThreadInterruptedException) {
                            // TODO Keep waiting until full wait expired?
                        }
                        if (_receivingQueue.Count < 1) {
                            return -1;
                        }
                    }

                    byte[] packet;
                    _receivingQueue.TryDequeue(out packet);
                    int copyLength = System.Math.Min(len, packet.Length);
                    Array.Copy(packet, 0, buf, off, copyLength);
                    Debug.Print($"OurTransport::Receive - EP:{_ep} Data Length: {packet.Length}");
                    Debug.Print(BitConverter.ToString(buf, off, copyLength));
                    return copyLength;
                }
            }

            public void Send(byte[] buf, int off, int len)
            {
                Debug.Print($"OurTransport::Send Data Length: {len}");
                Debug.Print(BitConverter.ToString(buf, off, len));
                byte[] newBuf = new byte[len];
                Array.Copy(buf, off, newBuf, 0, newBuf.Length);
                buf = newBuf;
                _udpChannel.Send(buf, _ep);
            }

            private readonly ConcurrentQueue<byte[]> _receivingQueue = new ConcurrentQueue<byte[]>();

            public void Receive(byte[] buf)
            {
                lock (_receivingQueue) {
                    _receivingQueue.Enqueue(buf);
                    Monitor.PulseAll(_receivingQueue);
                }
            }

        }
    }
}
