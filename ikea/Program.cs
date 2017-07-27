using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Com.AugustCellars.COSE;
using PeterO.Cbor;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Net;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.Log;
using Com.AugustCellars.CoAP.Util;

namespace ikea
{
    class Program
    {
        static void Main(string[] args)
        {
            Com.AugustCellars.CoAP.Log.LogManager.Level = LogLevel.None;
            ;
            String Server = "192.168.53.55:5684";

            OneKey userKey = new OneKey();
            userKey.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            //userKey.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(Encoding.UTF8.GetBytes("sesame")));
            // userKey.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(Encoding.UTF8.GetBytes("password")));

            CoapClient client = new CoapClient(new Uri($"coaps://{Server}/.well-known/core"));
            
      


            CoAPEndPoint ep = new DTLSClientEndPoint(userKey);
            client.EndPoint = ep;
            ep.Start();

            //

            Response r1 = client.Get();
            Console.WriteLine("Links = " + r1.PayloadString);

            //
            //           string str = "<//15001/65536>;ct=0;obs,<//15001/65537>;ct=0;obs,<//15004/136834>;ct=0;obs,<//15005/136834/217609>;ct=0;obs,<//15005/136834/218326>;ct=0;obs,<//15005/136834/224384>;ct=0;obs,<//15005/136834>;ct=0;obs,<//15001>;ct=0;obs,<//15001/reset>;ct=0,<//status>;ct=0;obs,<//15005>;ct=0;obs,<//15004>;ct=0;obs,<//15004/add>;ct=0,<//15004/remove>;ct=0,<//15006>;ct=0;obs,<//15011/15012>;ct=0;obs,<//15011/9034>;ct=0,<//15011/9030>;ct=0,<//15011/9031>;ct=0,<//15011/9063>;ct=0,<//15011/9033>;ct=0,<//15010>;ct=0;obs";
            //           IEnumerable<WebLink> links = LinkFormat.Parse(str);
            //           foreach(var item in links) Console.WriteLine(item);
            //

            LogManager.Level = LogLevel.None;


            IEnumerable<WebLink> items = client.Discover();

            foreach (var node in items) {
                Console.WriteLine($"Resource = {node}");

                client.UriPath = node.Uri;

                if (false && node.Attributes.Observable) {
                    CoapClient c2 = new CoapClient() {
                        EndPoint = client.EndPoint,
                        Uri = client.Uri,
                        UriPath = node.Uri
                    };
                    Console.WriteLine("Observe it");
                    CoapObserveRelation relation1 = c2.Observe(r => { EventIn(node.Uri, r); });
                }
                else {
                    Response response = client.Get();

                    Console.WriteLine("   Payload: " + response.PayloadString);
                    Console.WriteLine();
                }
            }

            client.Uri = new Uri($"coaps://{Server}");
            client.UriPath = "/15004/166412";
            client.Get();
            Response rep = client.Put("{ \"5850\":1}");
            Thread.Sleep(3000);

            //rep = client.Get();
            Console.WriteLine(rep.PayloadString);

            client.UriPath = "/15001/65537";
            ;

            for (int i = 0; i < 10; i++) {
                Thread.Sleep(3000);
                client.Put("{ \"5851\":127}");

                Thread.Sleep(3000);
                client.Put("{ \"3311\":[{ \"5851\":0}]}");

                Thread.Sleep(3000);
                client.Put("{ \"3311\":[{ \"5851\":255}]}");
            }


            ep.Stop();
        }


        static void EventIn(String who, Response res)
        {
            Console.WriteLine("The notify {2} resource at {0} has a payload of {1}", who, res.ResponseText, res.Observe);
            PrintInfo(res.ResponseText);
            Console.WriteLine();
        }

        static void PrintInfo(string value)
        {
            CBORObject obj = CBORObject.FromJSONString(value);

            Console.WriteLine($"Name: {obj["9001"].AsString()}");
            obj.Remove(CBORObject.FromObject("9001"));

            Console.WriteLine(obj.ToString());
        }

    }
}
