#include "sys.h"
#include "GeoLocation.h"
#include "utils/has_to_string.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <vector>

#include "ResolverFlags.h"
#include "debug.h"

struct SDNS
{
  ResolverFlags protocol_;
  ResolverFlags flags_;
  std::string IP_;
  std::string country_code_;
  std::string asn_;
  float longitude_;
  float latitude_;
};

struct Resolver
{
  std::string name_;
  std::vector<SDNS> sdns_;
  ResolverFlags flags_;
  std::string unused_;
};

// Global map for string to flag conversion. Initialized once in main.
std::map<std::string, ResolverFlags> global_string_to_flag_map;

// Initializes the global_string_to_flag_map with canonical flag names.
void initialize_global_string_to_flag_map()
{
  if (!global_string_to_flag_map.empty()) return;

  global_string_to_flag_map["None"]                 = ResolverFlags::None;
  global_string_to_flag_map["NoFilter"]             = ResolverFlags::NoFilter;
  global_string_to_flag_map["NoLog"]                = ResolverFlags::NoLog;
  global_string_to_flag_map["NoPersistentLogs"]     = ResolverFlags::NoPersistentLogs;
  global_string_to_flag_map["DNSSEC"]               = ResolverFlags::DNSSEC;
  global_string_to_flag_map["Do53"]                 = ResolverFlags::Do53;
  global_string_to_flag_map["DNSCrypt"]             = ResolverFlags::DNSCrypt;
  global_string_to_flag_map["DoH"]                  = ResolverFlags::DoH;
  global_string_to_flag_map["DoT"]                  = ResolverFlags::DoT;
  global_string_to_flag_map["DoQ"]                  = ResolverFlags::DoQ;
  global_string_to_flag_map["oDoHRelay"]            = ResolverFlags::oDoHRelay;
  global_string_to_flag_map["oDoHTarget"]           = ResolverFlags::oDoHTarget;
  global_string_to_flag_map["DNSCryptRelay"]        = ResolverFlags::DNSCryptRelay;
  global_string_to_flag_map["IPv4"]                 = ResolverFlags::IPv4;
  global_string_to_flag_map["IPv6"]                 = ResolverFlags::IPv6;
  global_string_to_flag_map["NoECS"]                = ResolverFlags::NoECS;
  global_string_to_flag_map["IncompatibleWithAnon"] = ResolverFlags::IncompatibleWithAnon;
  global_string_to_flag_map["GFWFiltering"]         = ResolverFlags::GFWFiltering;
  global_string_to_flag_map["HTTP3"]                = ResolverFlags::HTTP3;
  global_string_to_flag_map["QNAMEMinimization"]    = ResolverFlags::QNAMEMinimization;
  global_string_to_flag_map["MalwareBlocking"]      = ResolverFlags::MalwareBlocking;
  global_string_to_flag_map["AdBlocking"]           = ResolverFlags::AdBlocking;
  global_string_to_flag_map["TrackingBlocking"]     = ResolverFlags::TrackingBlocking;
  global_string_to_flag_map["SocialMediaBlocking"]  = ResolverFlags::SocialMediaBlocking;
  global_string_to_flag_map["FamilyFilter"]         = ResolverFlags::FamilyFilter;
  global_string_to_flag_map["Anycast"]              = ResolverFlags::Anycast;
  global_string_to_flag_map["NoPadding"]            = ResolverFlags::NoPadding;
}

// Parses a string (potentially pipe-separated) into ResolverFlags.
ResolverFlags parse_resolver_flags_from_json_string(std::string const& flags_str)
{
  if (flags_str.empty()) { return ResolverFlags::None; }
  if (flags_str == "None")
  {  // "None" string maps to the 0 value
    return ResolverFlags::None;
  }

  ResolverFlags result = ResolverFlags::None;
  std::stringstream ss(flags_str);
  std::string segment;

  while (std::getline(ss, segment, '|'))
  {
    auto it = global_string_to_flag_map.find(segment);
    if (it != global_string_to_flag_map.end()) { result |= it->second; }
    else { Dout(dc::notice, "Warning: Unknown flag string component: [" << segment << "] in flag string: [" << flags_str << "]"); }
  }
  return result;
}

std::vector<Resolver> parse(char const* filename, std::map<std::string, GeoLocation> const& locations)
{
  std::vector<Resolver> resolvers;

  std::ifstream file(filename);

  nlohmann::json j;
  try
  {
    // Read the entire file content and parse it as JSON
    file >> j;
  }
  catch (nlohmann::json::parse_error const& e)
  {
    // This will catch errors if the JSON is malformed.
    // The example JSON in the prompt for `sdns` field has syntax errors.
    // This code assumes `public-resolvers.json` is a valid JSON file.
    Dout(dc::notice, "JSON parsing error: " << e.what() << " at byte " << e.byte);
    // Return empty vector.
    return resolvers;
  }

  // Expecting the root of the JSON to be an array
  if (!j.is_array())
  {
    Dout(dc::notice, "Error: JSON root is not an array.");
    // Return empty vector.
    return resolvers;
  }

  for (auto const& resolver_json_obj : j)
  {
    if (!resolver_json_obj.is_object())
    {
      Dout(dc::notice, "Warning: Encountered non-object element in root array. Skipping.");
      continue;
    }
    Resolver current_resolver;

    // Parse "name"
    if (resolver_json_obj.contains("name") && resolver_json_obj["name"].is_string())
    {
      current_resolver.name_ = resolver_json_obj["name"].get<std::string>();
    }
    else
    {
      Dout(dc::notice, "Warning: Resolver entry missing or has invalid 'name'. Name will be empty for this entry.");
    }

    // Parse "flags" for Resolver
    if (resolver_json_obj.contains("flags") && resolver_json_obj["flags"].is_string())
    {
      current_resolver.flags_ = parse_resolver_flags_from_json_string(resolver_json_obj["flags"].get<std::string>());
    }
    else
    {
      current_resolver.flags_ = ResolverFlags::None;  // Default
    }

    // Parse "unused" field for Resolver (if it exists).
    if (resolver_json_obj.contains("unused") && resolver_json_obj["unused"].is_string())
    {
      current_resolver.unused_ = resolver_json_obj["unused"].get<std::string>();
    }

    // Parse "sdns" array.
    if (resolver_json_obj.contains("sdns") && resolver_json_obj["sdns"].is_array())
    {
      for (auto const& sdns_json_obj : resolver_json_obj["sdns"])
      {
        if (!sdns_json_obj.is_object())
        {
          Dout(dc::notice, "Warning: SDNS entry for resolver '" << current_resolver.name_ << "' is not an object. Skipping.");
          continue;
        }
        SDNS current_sdns;

        // Parse "protocol" for SDNS.
        if (sdns_json_obj.contains("protocol") && sdns_json_obj["protocol"].is_string())
        {
          current_sdns.protocol_ = parse_resolver_flags_from_json_string(sdns_json_obj["protocol"].get<std::string>());
        }
        else
        {
          current_sdns.protocol_ = ResolverFlags::None;  // Default
        }

        // Parse "flags" for SDNS.
        if (sdns_json_obj.contains("flags") && sdns_json_obj["flags"].is_string())
        {
          current_sdns.flags_ = parse_resolver_flags_from_json_string(sdns_json_obj["flags"].get<std::string>());
        }
        else
        {
          current_sdns.flags_ = ResolverFlags::None;  // Default
        }

        // Parse "IP" for SDNS.
        if (sdns_json_obj.contains("IP") && sdns_json_obj["IP"].is_string())
        {
          current_sdns.IP_ = sdns_json_obj["IP"].get<std::string>();
          auto gli = locations.find(current_sdns.IP_);
          if (gli == locations.end())
            throw std::runtime_error("No such IP: " + current_sdns.IP_);
          GeoLocation const& gl = gli->second;
          current_sdns.country_code_ = gl.country_code_;
          current_sdns.asn_ = gl.asn_;
          current_sdns.longitude_ = gl.longitude_;
          current_sdns.latitude_ = gl.latitude_;
        }
        else
        {
          Dout(dc::notice, "Warning: SDNS entry for resolver '" << current_resolver.name_ << "' missing or has invalid 'IP'. IP will be empty.");
        }
        // Add the parsed SDNS object to the current resolver's vector
        current_resolver.sdns_.push_back(current_sdns);
      }
    }
    // Add the parsed Resolver object to the main vector
    resolvers.push_back(current_resolver);
  }

  // At this point, `resolvers` vector is populated.
  // You can add code here to process or print the `resolvers` data.
  Dout(dc::notice, "Successfully parsed " << resolvers.size() << " resolvers.");

  return resolvers;
}

enum class DataSurveillanceGroup
{
  None,
  FiveEyes,
  NineEyesEU,
  NineEyes,
  FourteenEyes,
  EuropeanUnion,
  CnHkIrRu,
};

char const* to_string(DataSurveillanceGroup group)
{
  using enum DataSurveillanceGroup;
  switch (group)
  {
    AI_CASE_RETURN(None);
    case FiveEyes: return "5Eyes";
    case NineEyesEU: return "9EyesEU";
    case NineEyes: return "9Eyes";
    case FourteenEyes: return "14Eyes";
    AI_CASE_RETURN(EuropeanUnion);
    AI_CASE_RETURN(CnHkIrRu);
  }
  AI_NEVER_REACHED
}

std::ostream& operator<<(std::ostream& os, DataSurveillanceGroup group)
{
  os << to_string(group);
  return os;
}

bool compatible(DataSurveillanceGroup a, DataSurveillanceGroup b)
{
  using enum DataSurveillanceGroup;
  // One is not in any of the coalitions.
  if (a == None || b == None)
    return true;
  // They are in the same group.
  if (a == b)
    return false;
  // They are both part of the EU.
  if (a == NineEyesEU && b == EuropeanUnion)
    return false;
  if (a == EuropeanUnion && b == NineEyesEU)
    return false;
  // They are both part of the 14Eyes.
  bool a_eyes = a == FiveEyes || a == NineEyesEU || a == NineEyes || a == FourteenEyes;
  bool b_eyes = b == FiveEyes || b == NineEyesEU || b == NineEyes || b == FourteenEyes;
  if (a_eyes && b_eyes)
    return false;
  return true;
}

bool is_european_union(std::string const& country_code)
{
  // From https://ec.europa.eu/eurostat/statistics-explained/index.php?title=Glossary:European_Union_(EU)
  return
    (country_code == "AT" || // Austria
     country_code == "BE" || // Belgium
     country_code == "BG" || // Bulgaria
     country_code == "HR" || // Croatia
     country_code == "CY" || // Cyprus
     country_code == "CZ" || // Czechia
     country_code == "DK" || // Denmark
     country_code == "EE" || // Estonia
     country_code == "FI" || // Finland
     country_code == "FR" || // France
     country_code == "DE" || // Germany
     country_code == "EL" || // Greece
     country_code == "HU" || // Hungary
     country_code == "IE" || // Ireland
     country_code == "IT" || // Italy
     country_code == "LV" || // Latvia
     country_code == "LT" || // Lithuania
     country_code == "LU" || // Luxembourg
     country_code == "MT" || // Malta
     country_code == "NL" || // Netherlands
     country_code == "PL" || // Poland
     country_code == "PT" || // Portugal
     country_code == "RO" || // Romania
     country_code == "SK" || // Slovakia
     country_code == "SI" || // Slovenia
     country_code == "ES" || // Spain
     country_code == "SE");  // Sweden
}

DataSurveillanceGroup country_code_to_group(std::string const& country_code)
{
  if (country_code == "US" || // United States
      country_code == "GB" || // United Kingdom
      country_code == "AU" || // Australia
      country_code == "CA" || // Canada
      country_code == "NZ")   // New Zealand
    return DataSurveillanceGroup::FiveEyes;

  // 9Eyes and European Union.
  if (country_code == "FR" || // France
      country_code == "NL")   // Netherlands
    return DataSurveillanceGroup::NineEyesEU;

  if (country_code == "DK" || // Denmark
      country_code == "NO")   // Norway
    return DataSurveillanceGroup::NineEyes;

  // Match Fourteen Eyes is always EU.
  if (country_code == "DE" || // Germany
      country_code == "BE" || // Belgium
      country_code == "IT" || // Italy
      country_code == "ES" || // Spain
      country_code == "SE")   // Sweden
    return DataSurveillanceGroup::FourteenEyes;

  if (country_code == "CN" || // China
      country_code == "HK" || // Hong Kong
      country_code == "IR" || // Iran
      country_code == "RU")   // Russia
    return DataSurveillanceGroup::CnHkIrRu;

  if (is_european_union(country_code))
    return DataSurveillanceGroup::EuropeanUnion;

  return DataSurveillanceGroup::None;
}

struct CSV
{
  std::string name_;
  DataSurveillanceGroup group_;
  std::string country_code_;
  std::string asn_;
  float longitude_;
  float latitude_;

  void write_to(std::ostream& os) const;
};

char const* csv_header = "Name,Group,Code,ASN,Long,Lat";

void CSV::write_to(std::ostream& os) const
{
  os << name_ << "," << group_ << "," << country_code_ << "," << asn_ << "," << longitude_ << "," << latitude_ << "\n";
}

int main()
{
  Debug(NAMESPACE_DEBUG::init());

  std::map<std::string, GeoLocation> locations = parse_geolocation_file("geolocation.txt");

  Dout(dc::notice, "Parsed " << locations.size() << " geolocation entries.");

  // Initialize the flag string to enum map (call once).
  initialize_global_string_to_flag_map();

  std::vector<Resolver> resolvers = parse("public-resolvers.json", locations);

  if (resolvers.empty())
    return 1;

  std::vector<Resolver> relays = parse("relays.json", locations);

  if (relays.empty())
    return 1;

  std::vector<CSV> resolver_csvs;

  for (int r = 0; r < resolvers.size(); ++r)
  {
    auto const& resolver = resolvers[r];

    std::ostringstream oss;
    oss << '"' << resolver.name_ << "\": " /*<< print_flags(resolver.flags_) << ", "*/;
    oss << "[";

    ResolverFlags sdns_flags{};
    bool have_sdns = false;
    char const* sep = "";
    for (size_t i = 0; i < resolver.sdns_.size(); ++i)
    {
      auto const& sdns_entry = resolver.sdns_[i];

      // Make sure each sdna has the same flags: we can only use the resolver.name_, so there shouldn't be a difference between the listed stamps.
      if (i == 0)
        sdns_flags = sdns_entry.flags_;
      if (sdns_flags != sdns_entry.flags_)
        throw std::runtime_error("Inconsistent SDNS flags for " + resolver.name_);

      ResolverFlags flags = resolver.flags_ | sdns_entry.protocol_ | sdns_entry.flags_;
      using enum ResolverFlags;
      // Skip servers that can only do IPv6.
      if ((flags & (IPv4|IPv6)) == IPv6)
        continue;
      if ((flags & (NoLog|NoPersistentLogs|DNSCrypt|DNSSEC|IncompatibleWithAnon|GFWFiltering|QNAMEMinimization|NoFilter|NoPadding)) != (NoLog|DNSCrypt|DNSSEC|NoFilter))
        continue;
      if (sdns_entry.IP_.find(':') < sdns_entry.IP_.length())
        continue;
      if (sdns_entry.country_code_.empty())
        continue;

      oss << sep << '{' << sdns_entry.country_code_ << ", " << sdns_entry.asn_ << '}';
      sep = ", ";
      have_sdns = true;

      // Store the found resolver.
      resolver_csvs.emplace_back(resolver.name_, country_code_to_group(sdns_entry.country_code_), sdns_entry.country_code_, sdns_entry.asn_, sdns_entry.longitude_, sdns_entry.latitude_);
    }

    oss << "]";
    if (!resolver.unused_.empty())
      oss << ", unused info: " << resolver.unused_;

    if (have_sdns)
      std::cout << oss.str() << std::endl;
  }

  std::vector<CSV> relay_csvs;

  for (int r = 0; r < relays.size(); ++r)
  {
    auto const& relay = relays[r];

    std::ostringstream oss;
    oss << '"' << relay.name_ << "\": " << print_flags(relay.flags_) << ", ";
    oss << "[";

    ResolverFlags sdns_flags{};
    bool have_sdns = false;
    char const* sep = "";

    for (size_t i = 0; i < relay.sdns_.size(); ++i)
    {
      auto const& sdns_entry = relay.sdns_[i];

      // Make sure each sdna has the same flags: we can only use the relay.name_, so there shouldn't be a difference between the listed stamps.
      if (i == 0)
        sdns_flags = sdns_entry.flags_;
      if (sdns_flags != sdns_entry.flags_)
        throw std::runtime_error("Inconsistent SDNS flags for " + relay.name_);

      ResolverFlags flags = relay.flags_ | sdns_entry.protocol_ | sdns_entry.flags_;
      using enum ResolverFlags;
      // Skip servers that can only do IPv6.
      if ((flags & (IPv4|IPv6)) == IPv6)
        continue;
      // Skip relays in Swiss, United Kingdom or European Union.
      std::string const& rcc = sdns_entry.country_code_;
      if (rcc == "CH" || rcc == "GB" || is_european_union(rcc))
        continue;
      if (sdns_entry.IP_.find(':') < sdns_entry.IP_.length())
        continue;
      if (sdns_entry.country_code_.empty())
        continue;

      oss << sep << '{' << sdns_entry.IP_ << ", " << sdns_entry.country_code_ << ", " << sdns_entry.asn_ << '}';
      sep = ", ";
      have_sdns = true;

      // Store the found relay.
      relay_csvs.emplace_back(relay.name_, country_code_to_group(sdns_entry.country_code_), sdns_entry.country_code_, sdns_entry.asn_, sdns_entry.longitude_, sdns_entry.latitude_);
    }

    oss << "]";

    if (have_sdns)
      std::cout << oss.str() << std::endl;
  }

  // Write CSV's to file.
  {
    std::ofstream ofile("NoLog_DNSCrypt_DNSSEC_NoFilter_resolvers.csv");
    ofile << csv_header << '\n';
    for (CSV const& csv : resolver_csvs)
      csv.write_to(ofile);
  }

  {
    std::ofstream ofile("DNSCryptRelay.csv");
    ofile << csv_header << '\n';
    for (CSV const& csv : relay_csvs)
      csv.write_to(ofile);
  }

  //  { server_name='plan9dns-mx', via=['anon-cs-ch', 'anon-dnswarden-swiss'] }
  // Run over all relays that seem compatible with VPN provider.
  char const* sep2 = "";
  for (CSV const& resolver : resolver_csvs)
  {
    std::cout << sep2 << "  { server_name='" << resolver.name_ << "', via=[";
    char const* sep = "";
    for (CSV const& relay : relay_csvs)
    {
      if (!compatible(relay.group_, resolver.group_))
        continue;
      if (relay.asn_ == resolver.asn_)
        continue;
      if (resolver.name_.starts_with("dnscry.pt") && relay.name_.starts_with("dnscry.pt"))
        continue;
      std::cout << sep << "'" << relay.name_ << "'";
      sep = ", ";
    }
    std::cout << "] }";
    sep2 = ",\n";
  }
  std::cout << "\n";
}
