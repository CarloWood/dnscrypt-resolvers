#include "sys.h"
#include "GeoLocation.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include "debug.h"

// Function to parse the geolocation file.
std::map<std::string, GeoLocation> parse_geolocation_file(std::string const& filename)
{
  std::map<std::string, GeoLocation> geo_data_map;
  std::ifstream file(filename);

  if (!file.is_open())
  {
    Dout(dc::warning, "Could not open geolocation file: " << filename);
    return geo_data_map;  // Return empty map
  }

  std::string line;
  std::string current_ip_key;
  int line_number = 0;

  while (std::getline(file, line))
  {
    line_number++;
    // Trim whitespace (optional, but good for robustness)
    // line.erase(0, line.find_first_not_of(" \t\n\r\f\v"));
    // line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);

    if (line.empty()) continue;  // Skip empty lines

    if (line.rfind("IP=", 0) == 0)
    {  // Check if line starts with "IP="
      if (line.length() > 3) { current_ip_key = line.substr(3); }
      else
      {
        Dout(dc::warning, "Malformed IP line at line " << line_number << ": " << line);
        current_ip_key.clear();  // Invalidate key for next line
      }
    }
    else
    {  // This line should be JSON
      if (current_ip_key.empty())
      {
        Dout(dc::warning, "JSON data found without preceding IP key at line " << line_number << ": " << line);
        continue;  // Skip this JSON data as we don't have a key
      }

      try
      {
        nlohmann::json geo_json = nlohmann::json::parse(line);
        GeoLocation loc;

        // Safely extract values, providing defaults or logging if missing/wrong type
        if (geo_json.contains("country_code") && geo_json["country_code"].is_string())
        {
          loc.country_code_ = geo_json["country_code"].get<std::string>();
        }
        else
        {
          Dout(dc::notice, "IP: " << current_ip_key << " - 'country_code' missing or not a string.");
        }

        if (geo_json.contains("country_name") && geo_json["country_name"].is_string())
        {
          loc.country_name_ = geo_json["country_name"].get<std::string>();
        }
        else
        {
          Dout(dc::notice, "IP: " << current_ip_key << " - 'country_name' missing or not a string.");
        }

        if (geo_json.contains("city_name") && geo_json["city_name"].is_string())
        {
          loc.city_name_ = geo_json["city_name"].get<std::string>();
        }
        else
        {
          Dout(dc::notice, "IP: " << current_ip_key << " - 'city_name' missing or not a string.");
        }

        if (geo_json.contains("latitude") && geo_json["latitude"].is_number())
        {
          loc.latitude_ = geo_json["latitude"].get<float>();
        }
        else
        {
          Dout(dc::notice, "IP: " << current_ip_key << " - 'latitude' missing or not a number, defaulting to 0.0.");
        }

        if (geo_json.contains("longitude") && geo_json["longitude"].is_number())
        {
          loc.longitude_ = geo_json["longitude"].get<float>();
        }
        else
        {
          Dout(dc::notice, "IP: " << current_ip_key << " - 'longitude' missing or not a number, defaulting to 0.0.");
        }

        if (geo_json.contains("asn"))
        {
          if (geo_json["asn"].is_string())
          {
            loc.asn_ = geo_json["asn"].get<std::string>();
          }
          else if (geo_json["asn"].is_number())
          {
            // Convert number to string if ASN is provided as a number in JSON
            loc.asn_ = std::to_string(geo_json["asn"].get<long long>());
          }
          else
          {
            Dout(dc::notice, "IP: " << current_ip_key << " - 'asn' is not a string or number.");
          }
        }
        else
        {
          Dout(dc::notice, "IP: " << current_ip_key << " - 'asn' missing.");
        }

        geo_data_map[current_ip_key] = loc;
        current_ip_key.clear();  // Clear key after use, ready for next "IP="
      }
      catch (nlohmann::json::parse_error const& e)
      {
        Dout(dc::warning, "JSON parsing error for IP " << current_ip_key << " at line " << line_number << ": " << e.what());
        current_ip_key.clear();  // Don't try to reuse this key
      }
      catch (nlohmann::json::type_error const& e)
      {
        Dout(dc::warning, "JSON type error for IP " << current_ip_key << " at line " << line_number << ": " << e.what());
        current_ip_key.clear();
      }
    }
  }

  if (!current_ip_key.empty())
    Dout(dc::warning, "File ended with an IP key ('" << current_ip_key << "') but no subsequent JSON data.");

  return geo_data_map;
}
