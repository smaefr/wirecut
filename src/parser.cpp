// SPDX-License-Identifier: MIT
// Copyright (c) 2025 smae

#include "wirecut/parser.hpp"

namespace wirecut {
namespace {

ParseResult fail(ParseStatus status) {
    ParseResult result;
    result.status = status;
    return result;
}

bool magic_matches(const std::uint8_t* data) {
    return data[0] == kMagic[0] && data[1] == kMagic[1] && data[2] == kMagic[2] &&
           data[3] == kMagic[3];
}

std::uint16_t read_be16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[0]) << 8) | static_cast<std::uint16_t>(data[1]));
}

} // namespace

const char* status_string(ParseStatus status) {
    switch (status) {
        case ParseStatus::Ok:
            return "ok";
        case ParseStatus::Truncated:
            return "truncated";
        case ParseStatus::Oversize:
            return "oversize";
        case ParseStatus::BadMagic:
            return "bad_magic";
        case ParseStatus::BadVersion:
            return "bad_version";
        case ParseStatus::LengthOverflow:
            return "length_overflow";
        case ParseStatus::TlvCountMismatch:
            return "tlv_count_mismatch";
    }
    return "unknown";
}

ParseResult parse(const std::uint8_t* data, std::size_t size) {
    if (size > kMaxFrameSize) {
        return fail(ParseStatus::Oversize);
    }
    if (data == nullptr || size < 6) {
        return fail(ParseStatus::Truncated);
    }
    if (!magic_matches(data)) {
        return fail(ParseStatus::BadMagic);
    }

    const std::uint8_t version = data[4];
    if (version != kVersion) {
        return fail(ParseStatus::BadVersion);
    }

    const std::uint8_t n_tlvs = data[5];
    std::size_t offset = 6;

    Packet packet;
    packet.version = version;
    packet.tlvs.reserve(n_tlvs);

    for (std::uint8_t i = 0; i < n_tlvs; ++i) {
        const std::size_t remain = size - offset;
        if (remain == 0) {
            return fail(ParseStatus::TlvCountMismatch);
        }
        if (remain < 3) {
            return fail(ParseStatus::Truncated);
        }

        const std::uint8_t tag = data[offset];
        const std::uint16_t length = read_be16(data + offset + 1);

        // Historical bug (FIXED): value bytes were copied using the untrusted
        // `length` field without checking that length <= remain - 3. ASan
        // reported a heap-buffer-overflow (see FUZZING.md). The check below is
        // required before any access of the value region.
#ifndef WIRECUT_HISTORICAL_UNSAFE
        if (static_cast<std::size_t>(length) > remain - 3) {
            return fail(ParseStatus::LengthOverflow);
        }
#endif

        const std::uint8_t* value_ptr = data + offset + 3;
        Tlv tlv;
        tlv.tag = tag;
        tlv.value.assign(value_ptr, value_ptr + length);
        packet.tlvs.push_back(std::move(tlv));
        offset += 3 + static_cast<std::size_t>(length);
    }

    ParseResult result;
    result.status = ParseStatus::Ok;
    result.packet = std::move(packet);
    return result;
}

} // namespace wirecut
