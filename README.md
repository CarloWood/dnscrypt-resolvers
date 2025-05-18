This project reads [`public-resolvers.md`](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/public-resolvers.md)
and then produces a `public-resolvers.json` file that hopefully is actually JSON and contains entries like:

```
  {
    "name": "cleanbrowsing-family-ipv6",
    "sdns": [{"stamp": "sdns://AQMAAAAAAAAAFFsyYTBkOjJhMDA6MTo6XTo4NDQzILysMvrVQ2kXHwgy1gdQJ8MgjO7w6OmflBjcd2Bl1I8pEWNsZWFuYnJvd3Npbmcub3Jn",
              "protocol": "DNSCrypt", "flags": "NoLog|DNSSEC", "address": "[2a0d:2a00:1::]:8443",
              "pk": "bcac32fad54369171f0832d6075027c3208ceef0e8e99f9418dc776065d48f29", "provider": "cleanbrowsing.org", "IP": "2a0d:2a00:1::",
             {"stamp": "sdns://AQMAAAAAAAAAFFsyYTBkOjJhMDA6Mjo6XTo4NDQzILysMvrVQ2kXHwgy1gdQJ8MgjO7w6OmflBjcd2Bl1I8pEWNsZWFuYnJvd3Npbmcub3Jn",
              "protocol": "DNSCrypt", "flags": "NoLog|DNSSEC", "address": "[2a0d:2a00:2::]:8443",
              "pk": "bcac32fad54369171f0832d6075027c3208ceef0e8e99f9418dc776065d48f29", "provider": "cleanbrowsing.org", "IP": "2a0d:2a00:2::"],
    "info": ["Blocks access to adult, pornographic and explicit sites over IPv6. It also blocks proxy and VPN domains that are used to bypass the filters. Mixed content sites (like Reddit) are also blocked. Google, Bing and Youtube are set to the Safe Mode.",
             "Warning: This server is incompatible with anonymization."],
    "flags": "IPv6|IncompatibleWithAnon|FamilyFilter"
  },
```

The output, public-resolvers.json, is now added to this repository - so you don't have
to download and run this code. There is also a file `geolocation.txt` with the geolocation
data of the servers (that is, the listed IP). For example, for the above:
```
IP=2a0d:2a00:1::
{"ip":"2a0d:2a00:0001:0000:0000:0000:0000:0000","country_code":"CA","country_name":"Canada","region_name":"Ontario","city_name":"Toronto","latitude":43.65366,"longitude":-79.38292,
"zip_code":"M5P 2N7","time_zone":"-04:00","asn":"205157","as":"Daniel Cid","is_proxy":false}
IP=2a0d:2a00:2::
{"ip":"2a0d:2a00:0002:0000:0000:0000:0000:0000","country_code":"NL","country_name":"Netherlands (Kingdom of the)","region_name":"Noord-Holland","city_name":"Amsterdam","latitude":52.3785,
"longitude":4.89998,"zip_code":"1000","time_zone":"+02:00","asn":"205157","as":"Daniel Cid","is_proxy":false}
```

Note how, despite the actual locations being vastly different (Toronto vs Amsterdam),
the organization behind these are the same, as can be seen from the Autonomous System Number (`asn`).
