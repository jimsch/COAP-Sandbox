using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Codec;
using Com.AugustCellars.CoAP.Net;

using Com.AugustCellars.CoAP.TLS;

using Com.AugustCellars.COSE;

namespace Com.AugustCellars.CoAP.TLS
{
    public class DTLSClientEndPoint : CoAPEndPoint
    {
        /// <inheritdoc/>
        public DTLSClientEndPoint(OneKey userKey) : this(userKey, 0, CoapConfig.Default)
        {
        }

        /// <inheritdoc/>
        public DTLSClientEndPoint(OneKey userKey, ICoapConfig config) : this(userKey, 0, config)
        {
        }

        /// <inheritdoc/>
        public DTLSClientEndPoint(OneKey userKey, Int32 port) : this(userKey, new DTLSClientChannel(userKey, port), CoapConfig.Default)
        {
        }

        public DTLSClientEndPoint(OneKey userKey, Int32 port, ICoapConfig config) : this (userKey, new DTLSClientChannel(userKey, port), config)
        { }

        /// <inheritdoc/>
        public DTLSClientEndPoint(OneKey userKey, System.Net.EndPoint localEP) : this(userKey, localEP, CoapConfig.Default)
        {
        }

        /// <inheritdoc/>
        public DTLSClientEndPoint(OneKey userKey, System.Net.EndPoint localEP, ICoapConfig config) : this(userKey, new DTLSClientChannel(userKey, localEP), config)
        {
        }

        /// <summary>
        /// Instantiates a new DTLS endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="channel"></param>
        /// <param name="config"></param>
        public DTLSClientEndPoint(OneKey userKey, DTLSClientChannel channel, ICoapConfig config) : base(channel, config)
        {
            Stack.Remove(Stack.Get("Reliability"));
            MessageEncoder = UdpCoapMesageEncoder;
            MessageDecoder = UdpCoapMessageDecoder;
            _endpointSchema = "coaps";
        }


        static IMessageDecoder UdpCoapMessageDecoder(byte[] data)
        {
            return new Spec.MessageDecoder18(data);
        }

        static IMessageEncoder UdpCoapMesageEncoder()
        {
            return new Spec.MessageEncoder18();
        }
    }
}
