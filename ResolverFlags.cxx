#include "sys.h"
#include "utils/to_string.h"
#include "ResolverFlags.h"

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
    result += separator;
    result += utils::to_string(static_cast<ResolverFlags>((*it)()));
    separator = "|";
  }

  return result;
}
