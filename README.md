Work in progress.

Currently this produces a `public-resolvers.json` file that hopefully is actually JSON
and contains entries like:

```
  {
    "name": "blahdns-de-dnscrypt-v6",
    "sdns": [{"stamp": "sdns://AQMAAAAAAAAAG1syYTAxOjRmODpjMTc6ZWM2Nzo6MV06ODQ0MyDwRPCkhRTWv0NpkRQ3nwfF6IP-4Nd5_Xe-78yb9_M6gRsyLmRuc2NyeXB0LWNlcnQuYmxhaGRucy5jb20",
              "flags": "NoLog|DNSSEC|DNSCrypt", "pk": "", "provider": ""}],
    "flags": "NoLog|DNSSEC|NoECS|QNAMEMinimization|MalwareBlocking|AdBlocking|TrackingBlocking|DNSCrypt",
    "data": ""
  },
```
