using System;

using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;


namespace Com.AugustCellars.CoAP.TLS
{
    class TcpSession
    {
        private TcpClient _client;
        private readonly IPEndPoint _ipEndPoint;
        private QueueItem _toSend;
        private NetworkStream _stm;

        private readonly ConcurrentQueue<QueueItem> _queue = new ConcurrentQueue<QueueItem>();


        public TcpSession(IPEndPoint ipEndPoint, QueueItem toSend)
        {
            _ipEndPoint = ipEndPoint;
            _toSend = toSend;
        }

        public TcpSession(TcpClient client)
        {
            _client = client;
            _ipEndPoint = (IPEndPoint) client.Client.RemoteEndPoint;
        }

        public ConcurrentQueue<QueueItem> Queue { get { return _queue; } }

        public NetworkStream Stream
        {
            get
            {
                if (_stm == null) _stm = _client.GetStream();
                return _stm;
            }
        }

        public IPEndPoint EndPoint {  get { return _ipEndPoint; } }

        public void Connect()
        {
            _client = new TcpClient(_ipEndPoint.AddressFamily);

            _client.Connect(_ipEndPoint);

            _stm = _client.GetStream();

            //  Send over the capability block

            byte[] data = {0x10, 0xE1, 0x04};

            _stm.Write(data, 0, data.Length);
            _stm.Flush();

            //  

            _stm.Write(_toSend.Data, 0, _toSend.Length);
            _stm.Flush();
            _toSend = null;
        }


        private Int32 _writing;
        private readonly Object _writeLock = new Object();

        public void WriteData()
        {
            if (_queue.Count == 0) return;
            lock (_writeLock) {
                if (_writing > 0) return;
                _writing = 1;
            }

            while (Queue.Count > 0) {
                QueueItem q;
                if (!_queue.TryDequeue(out q)) break;

                _stm.Write(q.Data, 0, q.Data.Length);
            }

            lock (_writeLock) {
                _writing = 0;
                if (_queue.Count > 0) WriteData();
            }
        }

    }
}
