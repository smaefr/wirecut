// SPDX-License-Identifier: MIT
// Copyright (c) 2025 smae
//
// Trust boundary: only wirecut::parse() may inspect untrusted frame bytes.
// Callers must treat ParseResult::packet as valid solely when status is Ok.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace wirecut {

inline constexpr std::size_t kMaxFrameSize = 4096;
inline constexpr std::uint8_t kVersion = 1;
inline constexpr std::uint8_t kMagic[4] = {0x57, 0x43, 0x54, 0x31}; // "WCT1"

enum class ParseStatus {
    Ok,
    Truncated,
    Oversize,
    BadMagic,
    BadVersion,
    LengthOverflow,
    TlvCountMismatch,
};

struct Tlv {
    std::uint8_t tag = 0;
    std::vector<std::uint8_t> value;
};

struct Packet {
    std::uint8_t version = 0;
    std::vector<Tlv> tlvs;
};

struct ParseResult {
    ParseStatus status = ParseStatus::Truncated;
    Packet packet;

    bool ok() const { return status == ParseStatus::Ok; }
};

const char* status_string(ParseStatus status);

// Parse a complete WCT1 frame. Never reads past [data, data+size).
// `data` may be null only when `size` is 0.
ParseResult parse(const std::uint8_t* data, std::size_t size);

inline ParseResult parse(const std::vector<std::uint8_t>& data) {
    return parse(data.empty() ? nullptr : data.data(), data.size());
}

} // namespace wirecut
