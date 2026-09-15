// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_COMMON_ADDRESS_H
#define ZOOBC_COMMON_ADDRESS_H

#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

namespace zoobc {
namespace common {

class Address {
public:
    // Normalize address by removing all separators (- and _)
    static std::string Normalize(const std::string& address) {
        std::string normalized;
        normalized.reserve(address.length());

        for (char c : address) {
            if (c != '-' && c != '_') {
                // Convert to uppercase for consistency
                normalized += std::toupper(c);
            }
        }

        return normalized;
    }

    // Check if two addresses are equal (ignoring separators and case)
    static bool AreEqual(const std::string& addr1, const std::string& addr2) {
        return Normalize(addr1) == Normalize(addr2);
    }

    // Validate address format (supports both ZBC and ZNK)
    static bool IsValid(const std::string& address) {
        std::string normalized = Normalize(address);

        // Must start with ZBC or ZNK
        if (normalized.length() < 3) {
            return false;
        }

        std::string prefix = normalized.substr(0, 3);
        if (prefix != "ZBC" && prefix != "ZNK") {
            return false;
        }

        // Check all characters after prefix are valid base32
        const std::string base32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        for (size_t i = 3; i < normalized.length(); i++) {
            if (base32_alphabet.find(normalized[i]) == std::string::npos) {
                return false;
            }
        }

        return true;
    }

    // Format address with specified separator (8 groups of 8 characters)
    static std::string Format(const std::string& address, char separator = '_') {
        std::string normalized = Normalize(address);

        if (normalized.length() < 3) {
            return normalized;
        }

        // Extract prefix (ZBC or ZNK)
        std::string formatted = normalized.substr(0, 3);

        // Add separator every 8 characters after prefix
        for (size_t i = 3; i < normalized.length(); i++) {
            if ((i - 3) % 8 == 0) {
                formatted += separator;
            }
            formatted += normalized[i];
        }

        return formatted;
    }

    // Format with underscores (ZBC_XXXXXXXX_XXXXXXXX_... or ZNK_XXXXXXXX_XXXXXXXX_...)
    static std::string FormatWithUnderscores(const std::string& address) {
        return Format(address, '_');
    }

    // Format with dashes (ZBC-XXXXXXXX-XXXXXXXX-... or ZNK-XXXXXXXX-XXXXXXXX-...)
    static std::string FormatWithDashes(const std::string& address) {
        return Format(address, '-');
    }

    // Get raw address (normalized, no separators)
    static std::string GetRaw(const std::string& address) {
        return Normalize(address);
    }
};

}  // namespace common
}  // namespace zoobc

#endif  // ZOOBC_COMMON_ADDRESS_H
