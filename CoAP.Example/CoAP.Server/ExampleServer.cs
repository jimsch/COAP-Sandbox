using System;
using System.Text;
using Com.AugustCellars.CoAP.Examples.Resources;
using Com.AugustCellars.CoAP.Net;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.TLS;
using Com.AugustCellars.CoAP.DTLS;

using Com.AugustCellars.COSE;
using PeterO.Cbor;

namespace Com.AugustCellars.CoAP.Example
{
    public class ExampleServer
    {
        public static void Main(String[] args)
        {
            KeySet keys = new KeySet();

            OneKey key = new OneKey();
            key.Add(CoseKeyKeys.KeyType, COSE.GeneralValues.KeyType_Octet);
            key.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(Encoding.UTF8.GetBytes("password")));
            key.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(Encoding.UTF8.GetBytes("sesame")));
            keys.AddKey(key);


            CoapServer server = new CoapServer();
            // server.AddEndPoint(new TcpEndPoint(5683));
            server.AddEndPoint(new DTLSEndPoint(null, keys, 5684));

            server.Add(new HelloWorldResource("hello"));
            server.Add(new FibonacciResource("fibonacci"));
            server.Add(new StorageResource("storage"));
            server.Add(new ImageResource("image"));
            server.Add(new MirrorResource("mirror"));
            server.Add(new LargeResource("large"));
            server.Add(new CarelessResource("careless"));
            server.Add(new SeparateResource("separate"));
            server.Add(new TimeResource("time"));

            try
            {

                server.Start();

                Console.Write("CoAP server [{0}] is listening on", server.Config.Version);

                foreach (var item in server.EndPoints)
                {
                    Console.Write(" ");
                    Console.Write(item.LocalEndPoint);
                }
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
            server.Stop();
        }
    }
}
