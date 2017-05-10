using System;
using System.Text;
using System.Collections.Generic;
using NUnit.Framework;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Examples.Resources;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.Server.Resources;
using Com.AugustCellars.CoAP.TLS;
using Com.AugustCellars.COSE;


namespace CoAP.TLS.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestFixture]
    public class OneServer
    {
        private CoapServer _server;
        private Int32 _serverPort;

        public OneServer()
        {
            // TODO: Add constructor logic here
            //
        }

        [OneTimeSetUp]
        public void SetServer()
        {
            CreateServer();           //

        }

        [OneTimeTearDown
        ]
        public void KillServer()
        {
            if (_server != null) _server.Stop();
        }

        [Test]
        public void TestMethod1()
        {
            Uri uri = new Uri("coap+tls://localhost:" + _serverPort.ToString() +"/hello");
            CoapClient client= new CoapClient(uri);
            TcpEndPoint ep = new TcpEndPoint();
            ep.Start();
            client.EndPoint = ep;

            Response resp = client.Get();

            Assert.AreEqual(resp.StatusCode, StatusCode.Content);
        }

        private void CreateServer()
        {
            _server = new CoapServer();

            TcpEndPoint endpoint = new TcpEndPoint();
            _server.AddEndPoint(endpoint);

            _server.Add(new HelloWorldResource("hello"));

            _server.Start();

            _serverPort = ((System.Net.IPEndPoint) endpoint.LocalEndPoint).Port;
        }
    }
}
