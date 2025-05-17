Work in progress.

Currently this produces a `public-resolvers.json` file that hopefully is actually JSON
and contains entries like:

```
{ 
    "name": "blahdns-de-dnscrypt-v6",
    "sdns": [{"stamp": "sdns://AQMAAAAAAAAAG1syYTAxOjRmODpjMTc6ZWM2Nzo6MV06ODQ0MyDwRPCkhRTWv0NpkRQ3nwfF6IP-4Nd5_Xe-78yb9_M6gRsyLmRuc2NyeXB0LWNlcnQuYmxhaGRucy5jb20",
              "protocol": "DNSCrypt", "flags": "NoLog|DNSSEC", "address": "[2a01:4f8:c17:ec67::1]:8443",
              "pk": "f044f0a48514d6bf43699114379f07c5e883fee0d779fd77beefcc9bf7f33a81", "provider": "2.dnscrypt-cert.blahdns.com"],
    "info": ["DNSCrypt server. No Logging, filters ads, trackers and malware. DNSSEC ready, QNAME Minimization, No EDNS Client-Subnet."],
    "flags": "NoECS|QNAMEMinimization|MalwareBlocking|AdBlocking|TrackingBlocking"
  },

```

The output, public-resolvers.json, is now added to this repository - so you don't have
to download and run this code.
