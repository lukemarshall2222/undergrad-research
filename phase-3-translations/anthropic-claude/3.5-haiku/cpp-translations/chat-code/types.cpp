#include "types.hpp"
#include <sstream>
#include <iomanip>

namespace stream_processing {

IPv4Address IPv4Address::fromString(const std::string& str) {
    // Implement IP string parsing
    // This is a simplified version
    std::istringstream iss(str);
    uint8_t a, b, c, d;
    char dot;
    if (!(iss >> a >> dot >> b >> dot >> c >> dot >> d)) {
        throw std::invalid_argument("Invalid IP address format");
    }
    return IPv4Address((a << 24) | (b << 16) | (c << 8) | d);
}

std::string IPv4Address::toString() const {
    std::ostringstream oss;
    oss << ((address >> 24) & 0xFF) << "."
        << ((address >> 16) & 0xFF) << "."
        << ((address >> 8) & 0xFF) << "."
        << (address & 0xFF);
    return oss.str();
}

MACAddress::MACAddress(const std::array<uint8_t, 6>& bytes) : bytes(bytes) {}

std::string MACAddress::toString() const {
    std::ostringstream oss;
    for (size_t i = 0; i < 6; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(bytes[i]);
        if (i < 5) oss << ":";
    }
    return oss.str();
}

} // namespace stream_processing