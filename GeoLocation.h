#include <string>
#include <map>

struct GeoLocation
{
  std::string country_code_;
  std::string country_name_;
  std::string city_name_;
  std::string asn_;
  float longitude_;
  float latitude_;
};

std::map<std::string, GeoLocation> parse_geolocation_file(std::string const& filename);
