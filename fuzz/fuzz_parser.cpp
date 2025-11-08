// SPDX-License-Identifier: MIT
// Copyright (c) 2025 smae

#include "wirecut/parser.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const wirecut::ParseResult result = wirecut::parse(data, size);
    if (result.ok()) {
        volatile std::size_t sink = result.packet.tlvs.size();
        (void)sink;
        for (const wirecut::Tlv& tlv : result.packet.tlvs) {
            sink ^= tlv.tag;
            sink ^= tlv.value.size();
        }
        (void)sink;
    } else {
        (void)wirecut::status_string(result.status);
    }
    return 0;
}
