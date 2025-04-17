#include "filter.h"
bool matches_prefix(const std::string& address, const std::string& prefix) {
    return address.rfind(prefix, 0) == 0;
}
