#include "sys.h"
#include "utils/BitSet.h"
#include "utils/macros.h"
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <string>
#include <string_view>
#include <regex>
#include <vector>
#include <array>
#include <optional>
#include <cstddef>
#include <cstdint>
#include <cassert>
#include "debug.h"

// Helper: The Base64 decoding table (maps ASCII to 6-bit value, or -1 for invalid)
// Standard Base64 alphabet: A-Z, a-z, 0-9, +, /
static constexpr std::array<int8_t, 256> decoding_table = [] {
  std::array<int8_t, 256> table{};
  table.fill(-1); // Initialize all to invalid

  for (char c = 'A'; c <= 'Z'; ++c) table[static_cast<unsigned char>(c)] = c - 'A';          // 0-25
  for (char c = 'a'; c <= 'z'; ++c) table[static_cast<unsigned char>(c)] = c - 'a' + 26;    // 26-51
  for (char c = '0'; c <= '9'; ++c) table[static_cast<unsigned char>(c)] = c - '0' + 52;    // 52-61

  table[static_cast<unsigned char>('+')] = 62;
  table[static_cast<unsigned char>('/')] = 63;
  // Note: '=' padding characters will map to -1, they are handled by structure, not value.
  return table;
}();

std::optional<std::vector<std::byte>> decode_url_safe_base64(std::string_view encoded_string_sv)
{
  // 1. Create a mutable string and normalize URL-safe characters to standard Base64.
  std::string encoded_string(encoded_string_sv);
  std::replace(encoded_string.begin(), encoded_string.end(), '-', '+');
  std::replace(encoded_string.begin(), encoded_string.end(), '_', '/');

  // 2. Handle potentially omitted padding.
  // Base64 string length (without padding) must be a multiple of 4 after encoding.
  // If it's not, padding was omitted.
  // The original data length mod 3 determines padding:
  // len % 3 == 1 -> 2 padding chars (e.g., "Zg==" from "f") -> encoded len % 4 == 2
  // len % 3 == 2 -> 1 padding char  (e.g., "Zm8=" from "fo") -> encoded len % 4 == 3
  // len % 3 == 0 -> 0 padding chars (e.g., "Zm9v" from "foo") -> encoded len % 4 == 0
  size_t current_len = encoded_string.length();
  if (current_len == 0)
    return std::vector<std::byte>{}; // Empty input -> empty output

  // Add padding if necessary.
  if (current_len % 4 == 2)
    encoded_string += "==";
  else if (current_len % 4 == 3)
    encoded_string += "=";
  else if (current_len % 4 == 1)
    return std::nullopt; // Invalid Base64 length (e.g. "A").
  // After padding, length must be a multiple of 4.
  if (encoded_string.length() % 4 != 0)
    // This should theoretically not be reached if above logic is correct.
    return std::nullopt;

  std::vector<std::byte> decoded_bytes;
  // Estimate output size to reserve memory.
  // Each 4 Base64 chars become 3 bytes, minus padding.
  size_t num_padding_chars = 0;
  if (encoded_string.length() >= 1 && encoded_string.back() == '=')
    ++num_padding_chars;
  if (encoded_string.length() >= 2 && encoded_string[encoded_string.length() - 2] == '=')
    ++num_padding_chars;

  decoded_bytes.reserve((encoded_string.length() / 4 * 3) - num_padding_chars);

  uint32_t current_block = 0; // Holds 4x 6-bit values (24 bits)
  int chars_in_block = 0;

  for (size_t i = 0; i < encoded_string.length(); i += 4)
  {
    uint8_t b[4]; // To hold the 6-bit values of the 4 Base64 characters

    // Get the 4 characters for this block
    char c1 = encoded_string[i];
    char c2 = encoded_string[i + 1];
    char c3 = encoded_string[i + 2]; // Might be '='
    char c4 = encoded_string[i + 3]; // Might be '='

    // Convert characters to their 6-bit values.
    b[0] = decoding_table[static_cast<unsigned char>(c1)];
    b[1] = decoding_table[static_cast<unsigned char>(c2)];
    // b[2] and b[3] might be padding chars, which map to 0xff in the decoding table.
    // but we handle them based on char value '=' instead.

    if (b[0] == 0xff || b[1] == 0xff)
      return std::nullopt; // First two characters of a quartet must be valid Base64 chars.

    // Assemble the 24-bit value from the first two 6-bit values.
    uint32_t triplet = (static_cast<uint32_t>(b[0]) << 18) | (static_cast<uint32_t>(b[1]) << 12);

    // Byte 1 (always present if b[0] and b[1] are valid).
    decoded_bytes.push_back(static_cast<std::byte>((triplet >> 16) & 0xff));

    // Handle third character.
    if (c3 == '=')
    {
      // If c3 is padding, c4 must also be padding.
      if (c4 != '=')
        return std::nullopt;
      break; // End of data, processed 1 byte from this quartet.
    }
    b[2] = decoding_table[static_cast<unsigned char>(c3)];
    if (b[2] == 0xff)
      return std::nullopt; // c3 must be valid if not padding.
    triplet |= (static_cast<uint32_t>(b[2]) << 6);

    // Byte 2
    decoded_bytes.push_back(static_cast<std::byte>((triplet >> 8) & 0xff));

    // Handle fourth character.
    if (c4 == '=')
      break; // End of data, processed 2 bytes from this quartet.
    b[3] = decoding_table[static_cast<unsigned char>(c4)];
    if (b[3] == 0xff)
      return std::nullopt; // c4 must be valid if not padding.
    triplet |= static_cast<uint32_t>(b[3]);

    // Byte 3
    decoded_bytes.push_back(static_cast<std::byte>(triplet & 0xff));
  }

  return decoded_bytes;
}

// Helper function to escape strings for JSON
// Ensures characters like " \ \n \r \t etc. are properly escaped.
std::string escape_json_string(std::string const& s)
{
  std::string escaped_s;
  escaped_s.reserve(s.length());
  for (char c : s)
  {
    switch (c)
    {
      case '"':
        escaped_s += "\\\"";
        break;
      case '\\':
        escaped_s += "\\\\";
        break;
      case '\b':
        escaped_s += "\\b";
        break;
      case '\f':
        escaped_s += "\\f";
        break;
      case '\n':
        escaped_s += "\\n";
        break;
      case '\r':
        escaped_s += "\\r";
        break;
      case '\t':
        escaped_s += "\\t";
        break;
      // case '/': escaped_s += "\\/"; break; // Optional: if you need to escape '/'
      default:
        // Control characters (U+0000 to U+001F) must be escaped.
        if (static_cast<unsigned char>(c) < 0x20)
          escaped_s += std::format("\\u{:04x}", static_cast<unsigned char>(c));
        else { escaped_s += c; }
        break;
    }
  }
  return escaped_s;
}

enum class ResolverFlags : uint32_t
{
  None                 = 0,
  NoFilter             = 1 << 0,  // "no filter", "non-filtering", "unfiltered"
  NoLog                = 1 << 1,  // "no logs", "non-logging", "zero logs"
  NoPersistentLogs     = 1 << 2,  // "No persistent logs"
  DNSSEC               = 1 << 3,  // "dnssec", "supports dnssec"
  Do53                 = 1 << 4,  // Plain DNS server.
  DNSCrypt             = 1 << 5,  // "dnscrypt"
  DoH                  = 1 << 6,  // DoH, "DNS-over-HTTPS"
  DoT                  = 1 << 7,  // DoT, "DNS-over-TLS"
  DoQ                  = 1 << 8,  // DoQ - DNS-over-QUIC
  oDoHRelay            = 1 << 9,  // oDoH relay
  oDoHTarget           = 1 << 10,  // oDoH target
  DNSCryptRelay        = 1 << 11, // DNSCrypt relay
  IPv4                 = 1 << 12, // "ipv4"
  IPv6                 = 1 << 13, // "ipv6"
  NoECS                = 1 << 14, // "no ecs", "no edns client-subnet"
  IncompatibleWithAnon = 1 << 15, // "incompatible with dns anonymization", "incompatible with anonymization"
  GFWFiltering         = 1 << 16, // "gfw filtering", "gfw poisoning"
  HTTP3                = 1 << 17, // "http/3", "doh3"
  QNAMEMinimization    = 1 << 18, // "qname minimization"
  MalwareBlocking      = 1 << 19, // "malware blocking", "malicious domains", "phishing"
  AdBlocking           = 1 << 20, // "adblock", "blocks ads", "ad-filtering"
  TrackingBlocking     = 1 << 21, // "blocks trackers"
  SocialMediaBlocking  = 1 << 22, // "blocks social media"
  FamilyFilter         = 1 << 23, // "adult content blocking", "family safety", "parental control"
  Anycast              = 1 << 24, // "anycast"
  NoPadding            = 1 << 25, // "no padding" - it is very unclear if servers not mentioning padding DO have padding however.
};

char const* to_string(ResolverFlags flag)
{
  using enum ResolverFlags;
  switch (flag)
  {
    AI_CASE_RETURN(None);
    AI_CASE_RETURN(NoFilter);
    AI_CASE_RETURN(NoLog);
    AI_CASE_RETURN(NoPersistentLogs);
    AI_CASE_RETURN(DNSSEC);
    AI_CASE_RETURN(Do53);
    AI_CASE_RETURN(DoH);
    AI_CASE_RETURN(DoT);
    AI_CASE_RETURN(DoQ);
    AI_CASE_RETURN(oDoHRelay);
    AI_CASE_RETURN(oDoHTarget);
    AI_CASE_RETURN(DNSCryptRelay);
    AI_CASE_RETURN(IPv4);
    AI_CASE_RETURN(IPv6);
    AI_CASE_RETURN(NoECS);
    AI_CASE_RETURN(IncompatibleWithAnon);
    AI_CASE_RETURN(GFWFiltering);
    AI_CASE_RETURN(HTTP3);
    AI_CASE_RETURN(QNAMEMinimization);
    AI_CASE_RETURN(MalwareBlocking);
    AI_CASE_RETURN(AdBlocking);
    AI_CASE_RETURN(TrackingBlocking);
    AI_CASE_RETURN(SocialMediaBlocking);
    AI_CASE_RETURN(FamilyFilter);
    AI_CASE_RETURN(DNSCrypt);
    AI_CASE_RETURN(Anycast);
    AI_CASE_RETURN(NoPadding);
  }
  AI_NEVER_REACHED
}

std::string print_flags(ResolverFlags flags)
{
  std::string result;

  using mask_type = std::underlying_type_t<ResolverFlags>;
  utils::BitSet<mask_type> bits(static_cast<mask_type>(flags));

  if (bits.none())
    return "None";

  std::string separator;
  for (auto it = bits.begin(); it != bits.end(); ++it)
  {
    result += separator + to_string(static_cast<ResolverFlags>((*it)()));
    separator = "|";
  }

  return result;
}

// Helper operators for bitmask manipulation.
constexpr inline ResolverFlags operator|(ResolverFlags a, ResolverFlags b)
{
  return static_cast<ResolverFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

constexpr inline ResolverFlags& operator|=(ResolverFlags& a, ResolverFlags b)
{
  a = a | b;
  return a;
}

constexpr inline ResolverFlags operator&(ResolverFlags a, ResolverFlags b)
{
  return static_cast<ResolverFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

constexpr inline ResolverFlags& operator&=(ResolverFlags& a, ResolverFlags b)
{
  a = a & b;
  return a;
}

constexpr inline ResolverFlags operator~(ResolverFlags a)
{
  return static_cast<ResolverFlags>(~static_cast<uint32_t>(a));
}

constexpr ResolverFlags protocols = ResolverFlags::Do53 | ResolverFlags::DNSCrypt | ResolverFlags::DoH | ResolverFlags::DoT | ResolverFlags::DoQ |
  ResolverFlags::oDoHRelay | ResolverFlags::oDoHTarget | ResolverFlags::DNSCryptRelay;

// Helper to convert string to lowercase.
std::string toLower(std::string s)
{
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c){ return std::tolower(c); });
  return s;
}

// Helper to trim leading/trailing whitespace.
std::string trim(std::string const& str)
{
  std::string const whitespace = " \t\n\r\f\v";
  size_t start = str.find_first_not_of(whitespace);
  if (start == std::string::npos) // No non-whitespace content.
    return {};
  size_t end = str.find_last_not_of(whitespace);
  return str.substr(start, end - start + 1);
}

struct PhraseFlagsMapping
{
  std::string phrase_;
  ResolverFlags flags_;
};

struct RegexFlagsMapping
{
  std::regex regex_;
  ResolverFlags flags_;
};

// Global list of phrases that do not map to flags.
std::vector<std::string> g_noFlagPhrases;

// Global list of mappings - initialized once
std::vector<PhraseFlagsMapping> g_phrase_mapping;
std::vector<RegexFlagsMapping> g_regex_mapping;

void initializeMappings()
{
  // Prevent re-initialization.
  if (!g_phrase_mapping.empty())
    return;

  std::fstream noFlagPhrasesFile("no_flag_phrases.txt");
  if (!noFlagPhrasesFile.is_open())
  {
    std::cerr << "Error: Could not open 'no_flag_phrases.txt' for reading.\n";
    return;
  }
  std::string line;
  while (std::getline(noFlagPhrasesFile, line))
    g_noFlagPhrases.push_back(line);

  using enum ResolverFlags;

  g_phrase_mapping = {
    {"AdGuard DNS with safesearch and adult content blocking",
      FamilyFilter},
    {"AdGuard DNS with safesearch and adult content blocking (over DoH)",
      DoH|FamilyFilter},
    {"AdGuard DNS with safesearch and adult content blocking (over IPv6)",
      IPv6|FamilyFilter},
    {"AdGuard DNS with safesearch and adult content blocking (over DoH, over IPv6)",
      DoH|FamilyFilter|IPv6},
    {"AdGuard public DNS servers without filters (over DoH)",
      NoFilter|DoH},
    {"AdGuard public DNS servers without filters (over DoH, over IPv6)",
      NoFilter|DoH|IPv6},
    {"A DoH, DoT and DoQ resolver operated by sidnlabs.nl.",
      DoH|DoT|DoQ},
    {"No-logs, DNSSEC and No-filter.",
      NoLog|DNSSEC|NoFilter},
    {"A DoH, DoT and DoQ resolver operated by sidnlabs.nl over IPv6.",
      DoH|DoT|DoQ|IPv6},
    {"An open (non-logging, non-filtering, no ECS) DNSCrypt resolver operated by with IPv4 nodes anycast within AS41495 in the UK.",
      NoLog|NoFilter|NoECS|DNSCrypt|IPv4|Anycast},
    {"An open (non-logging, non-filtering, no ECS) DNSCrypt resolver operated by with IPv6 nodes anycast within AS41495 in the UK.",
      NoLog|NoFilter|NoECS|DNSCrypt|IPv6|Anycast},
    {"An open (non-logging, non-filtering, non-censoring) DNSCrypt resolver operated by Freifunk Munich with nodes in DE.",
      NoLog|NoFilter|DNSCrypt},
    {"An open (non-logging, non-filtering, non-censoring) DoH resolver operated by Freifunk Munich with nodes in DE.",
      NoLog|NoFilter|DoH},
    {"A public, non-tracking, non-filtering DNS resolver with DNSSEC enabled, QNAME minimization and no EDNS client subnet (",
      NoFilter|DNSSEC|QNAMEMinimization|NoECS},
    {"A zero logging DNS with support for DNS-over-HTTPS (DoH) & DNS-over-TLS (DoT).",
      NoLog|DoH|DoT},
    {"Blocks ads, malware, trackers, viruses, ransomware, telemetry and more.",
      AdBlocking|MalwareBlocking|TrackingBlocking},
    {"Barcelona, Spain DNSCrypt server provided by ",
      DNSCrypt},
    {"Belgrade, Serbia DNSCrypt server provided by ",
      DNSCrypt},
    {"Berlin, Germany DNSCrypt server provided by ",
      DNSCrypt},
    {"Block access to phishing, malware and malicious domains.",
      MalwareBlocking},
    {"It does not block adult content.",
      None},
    {"Blocks access to adult, pornographic and explicit sites.",
      FamilyFilter},
    {"Blocks access to adult, pornographic and explicit sites over DoH.",
      FamilyFilter|DoH},
    {"It also blocks proxy and VPN domains that are used to bypass the filters.",
      None},
    {"Mixed content sites (like Reddit) are also blocked.",
      FamilyFilter},
    {"Google, Bing and Youtube are set to the Safe Mode.",
      FamilyFilter},
    {"It does not block proxy or VPNs, nor mixed-content sites.",
      None},
    {"Google and Bing are set to the Safe Mode.",
      FamilyFilter},
    {"Blocks ads, malware, trackers and more.",
      AdBlocking|MalwareBlocking|TrackingBlocking},
    {"No persistent logs.",
      NoPersistentLogs},
    {"DNSSEC.",
      DNSSEC},
    {"No EDNS Client-Subnet.",
      NoECS},
    {"Blocks only phishing, spam and malicious domains over DoH.",
      MalwareBlocking|DoH},
    {"Bratislava, Slovakia DNSCrypt server provided by ",
      DNSCrypt},
    {"Brussels, Belgium DNSCrypt server provided by ",
      DNSCrypt},
    {"Canadian based, unfiltered, DNSSEC validating, and no logs...",
      NoFilter|DNSSEC|NoLog},
    {"Cloudflare DNS (anycast) - aka 1.1.1.1 / 1.0.0.1",
      Anycast},
    {"Cloudflare DNS (anycast) with malware blocking - aka 1.1.1.2 / 1.0.0.2",
      Anycast|MalwareBlocking},
    {"Cloudflare DNS (anycast) with malware protection and parental control - aka 1.1.1.3 / 1.0.0.3",
      Anycast|MalwareBlocking|FamilyFilter},
    {"Cloudflare DNS over IPv6 (anycast)",
      IPv6|Anycast},
    {"Cloudflare DNS over IPv6 (anycast) with malware blocking",
      IPv6|Anycast|MalwareBlocking},
    {"Cloudflare DNS over IPv6 (anycast) with malware protection and parental control",
      IPv6|Anycast|MalwareBlocking|FamilyFilter},
    {"Comodo Dome Shield (anycast) - ",
      Anycast},
    {"Comss.one DNS - DNS with adblock filters and antiphishing, gaining popularity among russian-speaking users.",
      AdBlocking|MalwareBlocking},
    {"Currently incompatible with DNS anonymization.",
      IncompatibleWithAnon},
    {"Denmark DNSCrypt server provided by ",
      DNSCrypt},
    {"DNSCrypt in Australia (Brisbane & Melbourne) by UserSpace.",
      DNSCrypt},
    {"No logs | IPv4 | Filtered",
      NoLog|IPv4},
    {"No logs | IPv6 | Filtered",
      NoLog|IPv6},
    {"DNSCrypt | IPv4 only | Non-logging | Non-filtering | DNSSEC | Frankfurt, Germany.",
      DNSCrypt|IPv4|NoLog|NoFilter|DNSSEC},
    {"DNSCrypt | IPv4 only | Non-logging | Non-filtering | DNSSEC | Paris, France.",
      DNSCrypt|IPv4|NoLog|NoFilter|DNSSEC},
    {"DNSCrypt, no filters, no logs, DNSSEC",
      DNSCrypt|NoFilter|NoLog|DNSSEC},
    {"DNSCrypt, no logs, uncensored, DNSSEC.",
      DNSCrypt|NoLog|NoFilter|DNSSEC},
    {"DNSCrypt on IPv4 (UDP/TCP).",
      DNSCrypt|IPv4},
    {"No DoH, doesn't log, doesn't filter, DNSSEC enforced.",
      NoLog|NoFilter|DNSSEC},
    {"No EDNS Client-Subnet, padding enabled, as per `dnscrypt-server-docker` default unbound configuration.",
      DNSCrypt|NoECS},
    {"DNSCrypt on IPv6 (UDP/TCP).",
      DNSCrypt|IPv6},
    {"Dnscrypt protocol.",
      DNSCrypt},
    {"Non-logging, non-filtering, DNSSEC.",
      NoLog|NoFilter|DNSSEC},
    {"DNSCrypt resolver hosted in Marseille, FR on Oracle Cloud.",
      DNSCrypt},
    {"No logs, no filters, DNSSEC.",
      NoLog|NoFilter|DNSSEC},
    {"DoH, DoH3 via the Alt-Svc header, no-logs, no-filters, DNSSEC",
      DoH|HTTP3|NoLog|NoFilter|DNSSEC},
    {"DNSCrypt server.",
      DNSCrypt},
    {"No Logging, filters ads, trackers and malware.",
      NoLog|AdBlocking|TrackingBlocking|MalwareBlocking},
    {"DNSSEC ready, QNAME Minimization, No EDNS Client-Subnet.",
      DNSSEC|QNAMEMinimization|NoECS},
    {"DNS-over-HTTPS server accessible over IPv6.",
      DoH|IPv6},
    {"Anycast, no logs, no censorship, DNSSEC.",
      Anycast|NoLog|NoFilter|DNSSEC},
    {"DNS-over-HTTPS server.",
      DoH},
    {"Anycast, no logs, no censorship, DNSSEC.",
      Anycast|NoLog|NoFilter|DNSSEC},
    {"DNS-over-HTTPS Server.",
      DoH},
    {"DNS-over-HTTPS Server (IPv6).",
      DoH|IPv6},
    {"Non-Logging, Non-Filtering, No ECS, Support DNSSEC.",
      NoLog|NoFilter|NoECS|DNSSEC},
    {"DNS-over-HTTPS server.",
      DoH},
    {"No Logging, filters ads, trackers and malware.",
      NoLog|AdBlocking|TrackingBlocking|MalwareBlocking},
    {"DNSSEC ready, QNAME Minimization, No EDNS Client-Subnet.",
      DNSSEC|QNAMEMinimization|NoECS},
    {"Non-Logging, Non-Filtering, No ECS, Support DNSSEC.",
      NoLog|NoFilter|NoECS|DNSSEC},
    {"DNSSEC-aware public resolver by the Taiwan Network Information Center (TWNIC) ",
      DNSSEC},
    {"DNSSEC, No-filter and No-log DoH resolver (IPv6) operated by Artikel10 association.",
      DNSSEC|NoFilter|NoLog|DoH|IPv6},
    {"DNSSEC, No-filter and No-log DoH resolver operated by Artikel10 association.",
      DNSSEC|NoFilter|NoLog|DoH},
    {"DNSSEC, No-log and No-filter DoH (IPv6) operated by RESTENA.",
      DNSSEC|NoLog|NoFilter|DoH|IPv6},
    {"DNSSEC, No-log and No-filter DoH operated by RESTENA.",
      DNSSEC|NoLog|NoFilter|DoH},
    {"DNSSEC/Non-logged/Uncensored in Amsterdam - DEV1-S instance donated by Scaleway.com Maintained by Frank Denis - ",
      DNSSEC|NoLog|NoFilter},
    {"DNSSEC/Non-logged/Uncensored in Amsterdam - IPv6 only - DEV1-S instance donated by Scaleway.com Maintained by Frank Denis - ",
      DNSSEC|NoLog|NoFilter|IPv6},
    {"DNSSEC/Non-logged/Uncensored in Paris - DEV1-S instance donated by Scaleway.com Maintained by Frank Denis - ",
      DNSSEC|NoLog|NoFilter},
    {"-DNSSEC/Non-logged/Uncensored in Paris - IPv6 only - DEV1-S instance donated by Scaleway.com Maintained by Frank Denis - ",
      DNSSEC|NoLog|NoFilter|IPv6},
    {"DNSSEC/Non-logged/Uncensored in Sydney (AWS).",
      DNSSEC|NoLog|NoFilter},
    {"DoH, no logs, no filter, anycast - ",
      DoH|NoLog|NoFilter|Anycast},
    {"DoH, no logs, no filter, unicast hosted in Denmark - ",
      DoH|NoLog|NoFilter},
    {"DoH server in France operated by FDN - French Data Network (non-profit ISP) ",
      DoH},
    {"DoH server in Germany.",
      DoH},
    {"No logging, but no DNS padding and no DNSSEC support.",
      NoLog|NoPadding},
    {"no ads version, uses StevenBlack's host list: ",
      AdBlocking},
    {"DoH server operated by Internet Initiative Japan in Tokyo.",
      DoH},
    {"Blocks child pornography.",
      FamilyFilter},
    {"DoH server provided by Tsinghua University TUNA Association, located in mainland China, no GFW poisoning yet it has a manual blacklist.",
      DoH},
    {"DoH server runned by Qihoo 360, has logs, GFW filtering rules are applied.",
      DoH|GFWFiltering},
    {"Dublin, Ireland DNSCrypt server provided by ",
      DNSCrypt},
    {"Dusseldorf, Germany 3 DNSCrypt server provided by ",
      DNSCrypt},
    {"Family safety focused blocklist for over 2 million adult sites, as well as phishing and malware and more.",
     FamilyFilter|MalwareBlocking},
    {"Free to use, paid for customizing blocking for more categories+sites and viewing usage at my.safesurfer.io.",
      None},
    {"Logs taken for viewing usage, data never sold - ",
      None},
    {"Finland DNSCrypt server provided by ",
      DNSCrypt},
    {"France DNSCrypt server provided by ",
      DNSCrypt},
    {"Frankfurt, Germany DNSCrypt server provided by ",
      DNSCrypt},
    {"Free | Malware and phishing filtering | Zero logs | DNSSEC | Poland | | @dnscryptpl",
      MalwareBlocking|NoLog|DNSSEC},
    {"Free | No filtering | Zero logs | DNSSEC | Poland | | @dnscryptpl",
      NoFilter|NoLog|DNSSEC},
    {"Google DNS (anycast)",
      Anycast},
    {"Hosted on Vultr, jlongua.github.io/plan9-dns, DoT & DoQ supported.",
      DoT|DoQ},
    {"HTTP/3, DoH protocol.",
      HTTP3|DoH},
    {"Non-logging.",
      NoLog},
    {"Blocks ads, malware and trackers.",
      AdBlocking|MalwareBlocking|TrackingBlocking},
    {"DNSSEC enabled.",
      DNSSEC},
    {"Non-logging, non-filtering, DNSSEC.",
      NoLog|NoFilter|DNSSEC},
    {"IPv4 server | No filter | No logs | DNSSEC | Nuremberg, Germany (netcup) | Maintained by ",
      IPv4|NoFilter|NoLog|DNSSEC},
    {"Latvia DNSCrypt server provided by ",
      DNSCrypt},
    {"London, England DNSCrypt server provided by ",
      DNSCrypt},
    {"Madrid, Spain DNSCrypt server provided by ",
      DNSCrypt},
    {"Manchester, England DNSCrypt server provided by ",
      DNSCrypt},
    {"Mexico City, Mexico DNSCrypt server provided by ",
      DNSCrypt},
    {"Milan, Italy DNSCrypt server provided by ",
      DNSCrypt},
    {"Montreal, Canada DNSCrypt server provided by ",
      DNSCrypt},
    {"Netherlands DNSCrypt server provided by ",
      DNSCrypt},
    {"No log.",
      NoLog},
    {"No filter.",
      NoFilter},
    {"No-log, No-filter RethinkDNS, a stub (sky.rethinkdns.com hosted on Cloudflare) and recursive (max.rethinkdns.com hosted on fly.io) resolver The stub server strips identification parameters from the request and acts as a proxy to another recursive resolver.",
      NoLog|NoFilter},
    {"Non-filtering, No-logging, DNSSEC DoH operated by Andrews & Arnold LTD.",
      NoFilter|NoLog|DNSSEC|DoH},
    {"Non-filtering, No-logging, DNSSEC DoH over IPv6 operated by Andrews & Arnold LTD.",
      NoFilter|NoLog|DNSSEC|DoH|IPv6},
    {"Non-logging, AD-filtering, supports DNSSEC.",
      NoLog|AdBlocking|DNSSEC},
    {"Non-Logging DNSCrypt server located in Singapore.",
      NoLog|DNSCrypt},
    {"Filters out ads, trackers and malware, supports DNSSEC, provided by id-gmail.",
      AdBlocking|TrackingBlocking|MalwareBlocking|DNSSEC},
    {"Non-Logging DNS-over-HTTPS (HTTP/2 & HTTP/3) server located in Singapore.",
      NoLog|DoH|HTTP3},
    {"Filters out ads, trackers and malware, supports DNSSEC, provided by id-gmail.",
      AdBlocking|TrackingBlocking|MalwareBlocking|DNSSEC},
    {"Non-Logging DNS-over-HTTPS server, cached via Cloudflare.",
      NoLog|DoH},
    {"Filters out ads, trackers and malware, NO ECS, supports DNSSEC.",
      AdBlocking|TrackingBlocking|MalwareBlocking|NoECS|DNSSEC},
    {"Non-Logging DNS-over-HTTPS server (IPv6), cached via Cloudflare.",
      NoLog|DoH|IPv6},
    {"Filters out ads, trackers and malware, NO ECS, supports DNSSEC.",
      AdBlocking|TrackingBlocking|MalwareBlocking|NoECS|DNSSEC},
    {"Non-Logging, Non-Filtering DNSCrypt (IPv6) server in Japan.",
      NoLog|NoFilter|DNSCrypt|IPv6},
    {"Non-Logging, Non-Filtering DNSCrypt server in Japan.",
      NoLog|NoFilter|DNSCrypt},
    {"No ECS, Support DNSSEC",
      NoECS|DNSSEC},
    {"Non-Logging, Non-Filtering DNS-over-HTTPS (IPv6) server in Japan.",
      NoLog|NoFilter|DoH|IPv6},
    {"Non-Logging, Non-Filtering DNS-over-HTTPS server in Japan.",
      NoLog|NoFilter|DoH},
    {"Non-logging, non-filtering, supports DNSSEC.",
      NoLog|NoFilter|DNSSEC},
    {"Open, DNSSEC, No-log and No-filter DoH operated by ",
      DNSSEC|NoLog|NoFilter|DoH},
    {"Open, DNSSEC, No-log and No-filter DoH over IPv6 operated by ",
      DNSSEC|NoLog|NoFilter|DoH|IPv6},
    {"Oslo, Norway DNSCrypt server provided by ",
      DNSCrypt},
    {"Portugal DNSCrypt server provided by ",
      DNSCrypt},
    {"Prague, Czech Republic DNSCrypt server provided by ",
      DNSCrypt},
    {"Public DNSCrypt server in the Netherlands by ",
      DNSCrypt},
    {"Public DoH (IPv6) service provided by SWITCH in Switzerland.",
      DoH|IPv6},
    {"Provides protection against malware, but does not block ads.",
      MalwareBlocking},
    {"Public DoH service provided by SWITCH in Switzerland.",
      DoH},
    {"Provides protection against malware, but does not block ads.",
      MalwareBlocking},
    {"Public non-filtering, non-logging (audited), DNSSEC-capable, DNS-over-HTTPS resolver hosted by VPN provider Mullvad.",
      NoFilter|NoLog|DNSSEC|DoH},
    {"Anycast IPv4/IPv6 with servers in SE, DE, UK, US, AU, and SG.",
      Anycast|IPv4|IPv6},
    {"Quad9 (anycast) dnssec/no-log/filter 2620:fe::fe - 2620:fe::9 - 2620:fe::fe:9",
      Anycast|DNSSEC|NoLog|MalwareBlocking|IPv6},
      // According to Gemini 2.5 Pro Preview 05-06: For Quad9, their primary "filtered" service (like 9.9.9.9 and its IPv6 equivalent 2620:fe::fe)
      // specifically blocks malicious domains (phishing, malware, spyware command and control domains). This is their main value proposition for the filtered service.
    {"Quad9 (anycast) dnssec/no-log/filter 9.9.9.9 - 149.112.112.9 - 149.112.112.112",
      Anycast|DNSSEC|NoLog|MalwareBlocking|IPv4},
    {"Quad9 (anycast) dnssec/no-log/filter/ecs 2620:fe::11 - 2620:fe::fe:11",
      Anycast|DNSSEC|NoLog|MalwareBlocking|IPv6},
    {"Quad9 (anycast) dnssec/no-log/filter/ecs 9.9.9.11 - 149.112.112.11",
      Anycast|DNSSEC|NoLog|MalwareBlocking|IPv4},
    {"Quad9 (anycast) no-dnssec/no-log/no-filter 2620:fe::10 - 2620:fe::fe:10",
      Anycast|NoLog|NoFilter|IPv6},
    {"Quad9 (anycast) no-dnssec/no-log/no-filter 9.9.9.10 - 149.112.112.10",
      Anycast|NoLog|NoFilter|IPv4},
    {"Quad9 (anycast) no-dnssec/no-log/no-filter/ecs 2620:fe::12 - 2620:fe::fe:12",
      Anycast|NoLog|NoFilter|IPv6},
    {"Quad9 (anycast) no-dnssec/no-log/no-filter/ecs 9.9.9.12 - 149.112.112.12",
      Anycast|NoLog|NoFilter|IPv4},
    {"Remove ads and protect your computer from malware (over DoH)",
      AdBlocking|MalwareBlocking|DoH},
    {"Remove ads and protect your computer from malware (over DoH, over IPv6)",
      AdBlocking|MalwareBlocking|DoH|IPv6},
    {"Romania DNSCrypt server provided by ",
      DNSCrypt},
    {"Rome, Italy DNSCrypt server provided by ",
      DNSCrypt},
    {"Same as mullvad-doh but blocks ads and trackers.",
      AdBlocking|TrackingBlocking|NoLog|DNSSEC|DoH|Anycast|IPv4|IPv6},
      // mullvad-doh is described as: "Public non-filtering, non-logging (audited), DNSSEC-capable, DNS-over-HTTPS
      // resolver hosted by VPN provider Mullvad. Anycast IPv4/IPv6 with servers in SE, DE, UK, US, AU, and SG."
    {"Same as mullvad-doh but blocks ads, trackers, and malware.",
      AdBlocking|TrackingBlocking|MalwareBlocking|NoLog|DNSSEC|DoH|Anycast|IPv4|IPv6},
    {"Same as mullvad-doh but blocks ads, trackers, malware, adult content, and gambling.",
      AdBlocking|TrackingBlocking|MalwareBlocking|FamilyFilter|NoLog|DNSSEC|DoH|Anycast|IPv4|IPv6},
    {"Same as mullvad-doh but blocks ads, trackers, malware, adult content, gambling, and social media.",
      AdBlocking|TrackingBlocking|MalwareBlocking|FamilyFilter|SocialMediaBlocking|NoLog|DNSSEC|DoH|Anycast|IPv4|IPv6},
    {"Same as mullvad-doh but blocks ads, trackers, malware, and social media.",
      AdBlocking|TrackingBlocking|MalwareBlocking|SocialMediaBlocking|NoLog|DNSSEC|DoH|Anycast|IPv4|IPv6},
    {"Sao Paulo, Brazil DNSCrypt server provided by ",
      DNSCrypt},
    {"Singapore DNSCrypt server provided by ",
      DNSCrypt},
    {"Sofia, Bulgaria DNSCrypt server provided by ",
      DNSCrypt},
    {"South Korea DNSCrypt server provided by ",
      DNSCrypt},
    {"Sweden DNSCrypt server provided by ",
      DNSCrypt},
    {"Switzerland DNSCrypt server provided by ",
      DNSCrypt},
    {"Sydney, Australia DNSCrypt server provided by ",
      DNSCrypt},
    {"The unfiltered version of dns0.eu.",
      NoFilter},
    {"This DNS blocks Malware, Ads & Tracking, Adult Content and Drugs domains.",
      MalwareBlocking|AdBlocking|TrackingBlocking|FamilyFilter},
    {"This DNS blocks Malware, Ads & Tracking and Social Networks domains.",
      MalwareBlocking|AdBlocking|TrackingBlocking|SocialMediaBlocking},
    {"This DNS blocks Malware, Ads & Tracking domains.",
      MalwareBlocking|AdBlocking|TrackingBlocking},
    {"This DNS blocks Malware domains.",
      MalwareBlocking},
    {"This is a Unfiltered DNS, no DNS record blocking or manipulation here, if you want to block Malware, Ads & Tracking or Social Network domains, use the other ControlD DNS configs.",
      NoFilter},
    {"Tokyo, Japan DNSCrypt server provided by ",
      DNSCrypt},
    {"US - Atlanta, GA DNSCrypt server provided by ",
      DNSCrypt},
    {"US - Chicago, IL 2 DNSCrypt server provided by ",
      DNSCrypt},
    {"US - Dallas, TX DNSCrypt server provided by ",
      DNSCrypt},
    {"US - Las Vegas, NV DNSCrypt server provided by ",
      DNSCrypt},
    {"US - Los Angeles, CA DNSCrypt server provided by ",
      DNSCrypt},
    {"US - North Carolina DNSCrypt server provided by ",
      DNSCrypt},
    {"US - Oregon DNSCrypt server provided by ",
      DNSCrypt},
    {"US - Washington, DC DNSCrypt server provided by ",
      DNSCrypt},
    {"Vancouver, Canada DNSCrypt server provided by ",
      DNSCrypt},
    {"Warning: GFW filtering rules are applied by this resolver.",
      GFWFiltering},
    {"Warning: This server is incompatible with anonymization.",
      IncompatibleWithAnon},
    {"Warning: this server is incompatible with DNS anonymization.",
      IncompatibleWithAnon},
    {"Warsaw, Poland DNSCrypt server provided by ",
      DNSCrypt},
    {"Wien, Austria DNSCrypt server provided by ",
      DNSCrypt},
    {"Yandex public DNS server (anycast)",
      Anycast},
    {"Yandex public DNS server (anycast IPv6)",
      Anycast|IPv6},
    {"Yandex public DNS server with malware filtering (anycast)",
      MalwareBlocking|Anycast},
    {"Yandex public DNS server with malware filtering (anycast IPv6)",
      MalwareBlocking|Anycast|IPv6},
    {"AdGuard public DNS servers without filters",
      NoFilter},
    {"AdGuard public DNS servers without filters (over IPv6)",
      NoFilter|IPv6},
    {"This version blocks content not suitable for children.",
      FamilyFilter},
    {"A public DNS resolver over IPv6 that supports DoH/DoT in mainland China, provided by Alibaba-Cloud.",
      DoH|DoT|IPv6},
    {"A public DNS resolver that supports DoH/DoT in mainland China, provided by Alibaba-Cloud.",
      DoH|DoT},
    {"A public DNS resolver that supports DoH/DoT in mainland China, provided by dnspod/Tencent-cloud.",
      DoH|DoT},
    {"Blocks access to adult, pornographic and explicit sites over IPv6.",
      FamilyFilter|IPv6},
    {"Blocks only phishing, spam and malicious domains.",
      MalwareBlocking},
    {"Blocks only phishing, spam and malicious domains over IPv6.",
      MalwareBlocking|IPv6},
    {"DoH protocol and No logging.",
      DoH|NoLog},
    {"Block websites not suitable for children (DNSCrypt protocol)",
      FamilyFilter|DNSCrypt},
    {"Block websites not suitable for children (IPv6)",
      FamilyFilter|IPv6},
    {"Cisco OpenDNS over IPv6 (DNSCrypt protocol)",
      IPv6|DNSCrypt},
    {"Cisco OpenDNS over IPv6 (DoH protocol)",
      IPv6|DoH},
    {"Cisco OpenDNS Sandbox (anycast)",
      Anycast},
    {"Connects to NextDNS over IPv6.",
      IPv6},
    {"DNSSEC, Anycast, Non-logging, NoFilters",
      DNSSEC|Anycast|NoLog|NoFilter},
    {"(DNSCrypt Protocol) (Now supports DNSSEC).",
      DNSCrypt|DNSSEC},
    {"(DoH Protocol) (Now supports DNSSEC).",
      DoH|DNSSEC},
    {"Block adult websites, gambling websites, malwares, trackers and advertisements.",
      FamilyFilter|MalwareBlocking|AdBlocking|TrackingBlocking},
    {"(DoH Protocol) (Now supports DNSSEC) Block adult websites, gambling websites, malwares, trackers and advertisements.",
      DoH|DNSSEC|FamilyFilter|MalwareBlocking|AdBlocking|TrackingBlocking},
    {"(DNSCrypt Protocol) (Now supports DNSSEC) Block adult websites, gambling websites, malwares, trackers and advertisements.",
      DNSCrypt|DNSSEC|FamilyFilter|MalwareBlocking|AdBlocking|TrackingBlocking},
    {"It also enforces safe search in: Google, YouTube, Bing, DuckDuckGo and Yandex.",
      SocialMediaBlocking},
    {"Social websites like Facebook and Instagram are not blocked.",
      None},
    {"No DNS queries are logged.",
      NoLog},
    {"As of 26-May-2022 5.9 million websites are blocked and new websites are added to blacklist daily.",
      None},
    {"Completely free, no ads or any commercial motive.",
      None},
    {"Dnscrypt Server, No Logging, No Filters, DNSSEC, OpenNIC",
      DNSCrypt|NoLog|NoFilter|DNSSEC},
    {"dnslow.me is an open source project, also your advertisement and threat blocking, privacy-first, encrypted DNS.",
      AdBlocking|MalwareBlocking},
    {"All DNS requests will be protected with threat-intelligence feeds and randomly distributed to some other DNS resolvers.",
      None},
    {"DoH & DoT Server, No Logging, No Filters, DNSSEC",
      DoH|DoT|NoLog|NoFilter|DNSSEC},
    {"DoH server operated by CIRCL, Computer Incident Response Center Luxembourg.",
      DoH},
    {"DoH server runned by xTom.com.",
      DoH},
    {"No logs, no filtering, supports DNSSEC.",
      NoLog|NoFilter|DNSSEC},
    {"Hurricane Electric DoH server (anycast)",
      DoH|Anycast},
    {"NextDNS is a cloud-based private DNS service that gives you full control over what is allowed and what is blocked on the Internet.",
      None},
    {"DNSSEC, Anycast, Non-logging, NoFilters",
      DNSSEC|Anycast|NoLog|NoFilter},
    {"Non-logging DoH server in France operated by Stéphane Bortzmeyer.",
      NoLog|DoH},
    {"Non-logging DoH server in France operated by Stéphane Bortzmeyer (IPv6 only).",
      NoLog|DoH|IPv6},
    {"Non-logging DoH server in Sweden operated by Njalla.",
      NoLog|DoH},
    {"Non Logging, filters ads, trackers and malware.",
      NoLog|AdBlocking|TrackingBlocking|MalwareBlocking},
    {"Public DoH resolver operated by the Digital Society (",
      DoH},
    {"Public DoH resolver operated by the Foundation for Applied Privacy (",
      DoH},
    {"Public DoH resolver running with Pihole for Adblocking (",
      DoH|AdBlocking},
    {"Public IPv6 DoH resolver operated by the Digital Society (",
      IPv6|DoH},
    {"Remove ads and protect your computer from malware",
      AdBlocking|MalwareBlocking},
    {"Remove ads and protect your computer from malware (over IPv6)",
      AdBlocking|MalwareBlocking|IPv6},
    {"Remove your DNS blind spot (DNSCrypt protocol)",
      DNSCrypt},
    {"Remove your DNS blind spot (DoH protocol)",
      DoH},
    {"Uses deep learning to block adult websites.",
      FamilyFilter},
    {"Free, DNSSEC, no logs.",
      DNSSEC|NoLog},
    {"Wikimedia DNS over IPv6.",
      IPv6},
    {"Unlike other dnsforfamily servers, this one does not enforces safe search.",
      None},
  };

  g_regex_mapping = {
    {std::regex(R"(^DNSCry\.pt ([^ ]* ?){1,3} - DNSCrypt, no filter, no logs, DNSSEC support \(IPv4 server\)$)"), DNSCrypt|NoFilter|NoLog|DNSSEC|IPv4},
    {std::regex(R"(^DNSCry\.pt ([^ ]* ?){1,3} - DNSCrypt, no filter, no logs, DNSSEC support \(IPv6 server\)$)"), DNSCrypt|NoFilter|NoLog|DNSSEC|IPv6},
  };
}

ResolverFlags getFlagsFromString(std::string& sentence)
{
  initializeMappings(); // Make sure mappings are loaded.

  ResolverFlags detectedFlags = ResolverFlags::None;

  // Begin with removing urls uptil and including the first space.
  size_t url_start = sentence.find("http");
  // Make sure the next character is an optional 's' and then '://'.
  if (url_start != std::string::npos && url_start + 5 < sentence.length() &&
      sentence.substr(url_start + 4 + (sentence[url_start + 4] == 's' ? 1 : 0), 3) == "://")
  {
    size_t url_end = sentence.find(" ", url_start);
    if (url_end == std::string::npos)
      url_end = sentence.length();
    else
      ++url_end; // Include the space in the removal.
    sentence.erase(url_start, url_end - url_start);
  }

  std::cout << "Trying to get flags from: '" << sentence << "'\n";

  for (auto const& mapping : g_phrase_mapping)
    if (sentence == mapping.phrase_)
    {
      detectedFlags |= mapping.flags_;
      // Mark the sentence as processed.
      std::cout << "Phrase found! '" << mapping.phrase_ << "'\n";
      sentence.clear();
      return detectedFlags;
    }

  for (auto const& mapping : g_regex_mapping)
    if (std::regex_match(sentence, mapping.regex_))
    {
      detectedFlags |= mapping.flags_;
      // Mark the sentence as processed.
      std::cout << "Regex found!\n";
      sentence.clear();
      break;    // Only one regex should be possible.
    }

  return detectedFlags;
}

struct SDNS
{
  std::string encoding_;
  ResolverFlags flags_{ResolverFlags::None};
  std::string address_;
  // DNSCrypt
  std::string public_key_;
  std::string provider_name_;
  // DoH, DoT, DoQ, oDoH
  std::vector<std::string> hashi_;      // Not oDoH target.
  std::string hostname_port_;
  std::string path_;                    // Not DoT, DoQ.
};

// Structure to hold data for each entry.
struct DnsEntry
{
  std::string name_;
  ResolverFlags flags_;
  std::vector<SDNS> sdns_;
  std::vector<std::string> info_;
  std::string unused_;

 public:
  DnsEntry() = default;
  DnsEntry(std::string const& name) : name_(name), flags_{ResolverFlags::None} { }

  void print_on(std::ostream& os, char const* indentation) const;
  void process(std::string const& data);
  void process_sentence(std::string& sentence);
  void process_sdns(std::string const& sdns);
};

void DnsEntry::print_on(std::ostream& os, char const* indentation) const
{
  os << indentation << "\"name\": \"" << escape_json_string(name_) << "\",\n";
  os << indentation << "\"sdns\": [";
  std::string sep = "";
  for (SDNS const& sdns : sdns_)
  {
    os << sep << "{\"stamp\": \"" << escape_json_string(sdns.encoding_) << "\",\n";
    os << indentation << "          " <<
      "\"protocol\": \"" << escape_json_string(print_flags(sdns.flags_ & protocols)) << "\", "
      "\"flags\": \"" << escape_json_string(print_flags(sdns.flags_ & ~protocols)) << "\", "
      "\"address\": \"" << escape_json_string(sdns.address_) << "\",\n";
    sep = std::string{indentation} + "          ";
    if (!sdns.public_key_.empty())
    {
      os << sep << "\"pk\": \"" << escape_json_string(sdns.public_key_) << "\"";
      sep = ", ";
    }
    if (!sdns.provider_name_.empty())
    {
      os << sep << "\"provider\": \"" << escape_json_string(sdns.provider_name_) << "\"";
      sep = ", ";
    }
    if (!sdns.hostname_port_.empty())
    {
      os << sep << "\"hostname_port\": \"" << escape_json_string(sdns.hostname_port_) << "\"";
      sep = ", ";
    }
    if (!sdns.path_.empty())
    {
      os << sep << "\"path\": \"" << escape_json_string(sdns.path_) << "\"";
      sep = ", ";
    }
    if (!sdns.hashi_.empty())
    {
      os << "\"hashi\": [";
      std::string sep2 = "";
      for (std::string const& hashi : sdns.hashi_)
      {
        os << sep2 << "\"" << escape_json_string(hashi) << "\"";
        sep2 = ", ";
      }
      os << "]";
    }
    sep = ",\n" + std::string(indentation) + "         ";
  }
  os << "],\n";
  os << indentation << "\"info\": [";
  sep = "";
  for (std::string const& info : info_)
  {
    os << sep << "\"" << escape_json_string(info) << "\"";
    sep = ",\n" + std::string(indentation) + "         ";
  }
  os << "],\n";
  os << indentation << "\"flags\": \"" << escape_json_string(print_flags(flags_)) << "\"";
  if (!unused_.empty())
    os << ",\n" << indentation << "\"unused\": \"" << escape_json_string(unused_) << "\"\n";
  else
    os << "\n";
}

void DnsEntry::process_sentence(std::string& sentence)
{
  // Check if the sentence equals a phrase that do not map to flags.
  for (auto const& phrase : g_noFlagPhrases)
    if (sentence == phrase)
    {
      // Mark the sentence as processed.
      sentence.clear();
      return;
    }

  std::cout << std::format("Processing sentence: '{}'\n", sentence);
  flags_ |= getFlagsFromString(sentence);
}

void DnsEntry::process(std::string const& data)
{
  // Input: catenated string of lines without empty line in between
  // and not starting with '## ' or 'sdns://'.
  std::cout << std::format("Processing data: '{}'\n", data);
  info_.push_back(data);

  // Split the line up again in sentences with ". " as separator.
  std::string data_copy = data;
  size_t pos;
  while ((pos = data_copy.find(". ")) != std::string::npos)
  {
    std::string sentence = data_copy.substr(0, pos + 1);
    data_copy.erase(0, pos + 2);        // Remove the processed part.
    process_sentence(sentence);
    if (!sentence.empty())
    {
      if (!unused_.empty())
        unused_ += "|";
      unused_ += sentence;              // Keep the unused part.
    }
  }
  if (!data_copy.empty())
  {
    process_sentence(data_copy);        // Process the last part.
    if (!data_copy.empty())
    {
      if (!unused_.empty())
        unused_ += "|";
      unused_ += data_copy;             // Keep the unused part.
    }
  }
}

uint64_t read_props(std::byte const*& bytes)
{
  uint64_t props = 0;
  // The props is a little-endian 64 bit value.
  for (int i = 0; i < 8; ++i)
    props |= (static_cast<uint64_t>(std::to_integer<uint8_t>(bytes[i])) << (i * 8));
  bytes += 8;
  return props;
}

std::string read_LP(std::byte const*& bytes)
{
  std::string LP;
  size_t length = std::to_integer<uint8_t>(bytes[0]);
  for (size_t i = 1; i <= length; ++i)
    LP += static_cast<char>(std::to_integer<uint8_t>(bytes[i]));
  bytes += length + 1;
  return LP;
}

std::vector<std::string> read_VLP(std::byte const*& bytes)
{
  std::vector<std::string> VLP;
  for (;;)
  {
    std::string LP;
    int L = std::to_integer<int>(bytes[0]);
    int length = L & ~0x80;
    for (int i = 1; i <= length; ++i)
      LP += static_cast<char>(std::to_integer<uint8_t>(bytes[i]));
    bytes += length + 1;
    if (L == length)    // Last element?
      break;
  }
  return VLP;
}

std::string read_public_key(std::byte const*& bytes)
{
  std::string public_key;
  size_t length = std::to_integer<uint8_t>(bytes[0]);
  for (int i = 1; i <= length; ++i)
    public_key += std::format("{:02x}", std::to_integer<uint8_t>(bytes[i]));
  bytes += length + 1;
  return public_key;
}

void DnsEntry::process_sdns(std::string const& sdns)
{
  std::cout << std::format("Processing SDNS: '{}'\n", sdns);
  std::string_view sdns_view{sdns};
  sdns_view.remove_prefix(7); // Remove the "sdns://".
  std::optional<std::vector<std::byte>> bytes = decode_url_safe_base64(sdns_view);
  if (!bytes)
  {
    std::cerr << std::format("Error: Failed to decode SDNS '{}'.\n", sdns);
    return;
  }

  SDNS new_sdns{sdns};

  int protocol = std::to_integer<int>(bytes->at(0));
  std::byte const* bytes_ptr = bytes->data() + 1;
  uint64_t props = 0;
  std::string address_port;
  switch (protocol)
  {
    case 0x00: // Plain DNS stamps
      new_sdns.flags_ |= ResolverFlags::Do53;
      props = read_props(bytes_ptr);
      address_port = read_LP(bytes_ptr);
      break;
    case 0x01: // DNSCrypt stamps
      new_sdns.flags_ |= ResolverFlags::DNSCrypt;
      props = read_props(bytes_ptr);
      address_port = read_LP(bytes_ptr);
      new_sdns.public_key_ = read_public_key(bytes_ptr);
      new_sdns.provider_name_ = read_LP(bytes_ptr);
      break;
    case 0x02: // DNS-over-HTTPS stamps
      new_sdns.flags_ |= ResolverFlags::DoH;
      props = read_props(bytes_ptr);
      address_port = read_LP(bytes_ptr);        // Just address.
      new_sdns.hashi_ = read_VLP(bytes_ptr);
      new_sdns.hostname_port_ = read_LP(bytes_ptr); // hostname [:port].
      new_sdns.path_ = read_LP(bytes_ptr);      // path.
      // Optional bootstrap IP's follow.
      break;
    case 0x03: // DNS-over-TLS stamps
      new_sdns.flags_ |= ResolverFlags::DoT;
      props = read_props(bytes_ptr);
      address_port = read_LP(bytes_ptr);        // Just address.
      new_sdns.hashi_ = read_VLP(bytes_ptr);
      new_sdns.hostname_port_ = read_LP(bytes_ptr); // hostname [:port].
      new_sdns.path_ = read_LP(bytes_ptr);      // path.
      // Optional bootstrap IP's follow.
      break;
    case 0x04: // DNS-over-QUIC stamps
      new_sdns.flags_ |= ResolverFlags::DoQ;
      props = read_props(bytes_ptr);
      address_port = read_LP(bytes_ptr);        // Just address.
      new_sdns.hashi_ = read_VLP(bytes_ptr);
      new_sdns.hostname_port_ = read_LP(bytes_ptr); // hostname [:port].
      // Optional bootstrap IP's follow.
      break;
    case 0x05: // Oblivious DoH target stamps
      new_sdns.flags_ |= ResolverFlags::oDoHTarget;
      props = read_props(bytes_ptr);
      address_port = read_LP(bytes_ptr);        // hostname [:port].
      new_sdns.hostname_port_ = read_LP(bytes_ptr); // hostname [:port].
      new_sdns.path_ = read_LP(bytes_ptr);      // path.
      break;
    case 0x81: // Anonymized DNSCrypt relay stamps
      new_sdns.flags_ |= ResolverFlags::DNSCryptRelay;
      address_port = read_LP(bytes_ptr);        // Just address.
      break;
    case 0x85: // Oblivious DoH relay stamps
      new_sdns.flags_ |= ResolverFlags::oDoHRelay;
      props = read_props(bytes_ptr);
      address_port = read_LP(bytes_ptr);        // Just address.
      new_sdns.hashi_ = read_VLP(bytes_ptr);
      new_sdns.hostname_port_ = read_LP(bytes_ptr); // hostname [:port].
      new_sdns.path_ = read_LP(bytes_ptr);      // path.
      // Optional bootstrap IP's follow.
      break;
    default:
      std::cerr << std::format("Error: Unknown protocol in SDNS '{}'.\n", sdns);
      return;
  }

  if ((props & 0x01))                           // the server supports DNSSEC
    new_sdns.flags_ |= ResolverFlags::DNSSEC;
  if ((props & 0x02))                           // the server doesn’t keep logs
    new_sdns.flags_ |= ResolverFlags::NoLog;
  if ((props & 0x04))                           // the server doesn’t intentionally block domains
    new_sdns.flags_ |= ResolverFlags::NoFilter;

  new_sdns.address_ = address_port;
  sdns_.push_back(new_sdns);
}

void process_next_entry(DnsEntry& current_entry, std::string& data, std::vector<DnsEntry>& entries)
{
  if (!data.empty())
  {
    current_entry.process(data);
    data.clear();
  }
  if (!current_entry.unused_.empty())
  {
    std::cout << std::format("Unprocessed phrase: '{}'\n", current_entry.unused_);
  }
  // Do a sanity check: any of the SDNS flags that are set in the entry also must be set in the SDNS.
  using enum ResolverFlags;
  // The list of flags set by DnsEntry::process_sdns.
  ResolverFlags sdns_flags = protocols|DNSSEC|NoLog|NoFilter;
  ResolverFlags current_sdns_flags = None;
  for (SDNS const& sdns : current_entry.sdns_)
  {
    current_sdns_flags |= sdns.flags_;
    if ((sdns.flags_ & (current_entry.flags_ & sdns_flags)) != (current_entry.flags_ & sdns_flags))
    {
      ResolverFlags extra_flags = (current_entry.flags_ & sdns_flags) & ~sdns.flags_;
      // Lets not print a warning about the description containing DoT or DoQ, because that seems to be kinda normal (only sdns for DoH are given).
      if ((extra_flags & ~(DoT|DoQ)) == None)
        continue;
      std::cerr << "Warning: Inconsistent flags in SDNS '" << sdns.encoding_ << "'. "
        "The following flags are set in the description but not in the sdns: " << print_flags(extra_flags) << std::endl;
    }
  }
  // Remove flags that are set in any of the SDNS from the entry flags.
  current_entry.flags_ &= ~current_sdns_flags;
  entries.push_back(current_entry);
}

int main()
{
  Debug(NAMESPACE_DEBUG::init());
  std::string input_filename_str   = "public-resolvers.md";
  std::string output_json_filename = "public-resolvers.json";

  std::filesystem::path input_filepath(input_filename_str);

  // 1. Check if the file exists.
  if (!std::filesystem::exists(input_filepath))
  {
    std::cerr << std::format("Error: File '{}' does not exist.\n", input_filepath.string());
    return EXIT_FAILURE;
  }

  // 2. Open the file
  std::ifstream inputFile(input_filepath);  // Automatically opens in text mode

  // Check if the file was successfully opened
  if (!inputFile.is_open())
  {
    std::cerr << "Error: Could not open file '" << input_filepath << "'. Check permissions.\n";
    return EXIT_FAILURE;
  }

  std::cout << "\n--- Reading file: " << input_filepath << " ---\n";

  std::string line;
  std::string data;
  unsigned int line_number             = 0;
  std::string const entry_start_prefix = "## ";
  std::string const dns_stamp_prefix = "sdns://";
  bool header                          = true;
  bool saw_empty_line                  = true;

  std::vector<DnsEntry> entries;
  DnsEntry current_entry;       // The current entry being parsed.

  while (std::getline(inputFile, line))
  {
    ++line_number;
    std::string const trimmed_line = trim(line);

    // Skip empty lines.
    if (trimmed_line.empty())
    {
      if (!header && !data.empty())
      {
        current_entry.process(data);
        data.clear();
      }
      saw_empty_line = true;
      continue;
    }

    // Start of a new entry?
    if (line.starts_with(entry_start_prefix))
    {
      // If this is not the first entry, store the previously collected one.
      if (!header)
        process_next_entry(current_entry, data, entries);
      // We're no longer in the header section.
      header = false;

      // Start new entry.
      current_entry = DnsEntry{trim(line.substr(entry_start_prefix.length()))};
      continue;
    }
    else if (header)
      continue;

    // We are processing lines for an existing entry.
    if (line.starts_with(dns_stamp_prefix))
    {
      if (!data.empty())
      {
        current_entry.process(data);
        data.clear();
      }
      current_entry.process_sdns(trimmed_line);
    }
    else if (saw_empty_line)
      data = line;
    else
      data += " " + line;

    saw_empty_line = false;
  }

  // Add the last processed entry if it exists.
  if (!header && !current_entry.name_.empty())
    process_next_entry(current_entry, data, entries);

  inputFile.close();

  if (inputFile.bad())
    std::cerr << "\nError: Critical read error occurred from '" << input_filepath << "'.\n";
  else if (inputFile.fail() && !inputFile.eof())
    std::cerr << "\nError: Non-critical read error from '" << input_filepath << "'.\n";
  else
   std::cout << std::format("\n--- Finished reading {} lines from {}. Found {} entries. ---\n", line_number, input_filepath.string(), entries.size());

  // Write the collected entry names to the JSON output file.
  std::ofstream outputFile(output_json_filename);
  if (!outputFile.is_open())
  {
    std::cerr << "Error: Could not open output file '" << output_json_filename << "' for writing.\n";
    return EXIT_FAILURE;
  }

  std::cout << "--- Writing entries to JSON file: " << output_json_filename << " ---\n";

  outputFile << "[\n";

  char const* separator = "  ";
  for (DnsEntry const& entry : entries)
  {
    outputFile << separator << "{\n";
    entry.print_on(outputFile, "    ");
    outputFile << "  }";
    separator = ",\n  ";
  }

  outputFile << "\n]\n";
  outputFile.close();

  if (outputFile.fail())
  {
    std::cerr << "Error: An error occurred while writing to '" << output_json_filename << "'.\n";
    return EXIT_FAILURE;
  }

  std::cout << std::format("--- Successfully wrote {} entries to {} ---\n", entries.size(), output_json_filename);

  return EXIT_SUCCESS;
}
