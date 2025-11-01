// SPDX-License-Identifier: MIT
// Copyright (c) 2025 smae

#include "wirecut/parser.hpp"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

namespace {

std::vector<std::uint8_t> read_all(std::istream& in) {
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());
}

void print_summary(const std::vector<std::uint8_t>& buf, const wirecut::ParseResult& result) {
    std::printf("status=%s bytes=%zu\n", wirecut::status_string(result.status), buf.size());
    if (!result.ok()) {
        return;
    }
    std::printf("version=%u n_tlvs=%zu\n", static_cast<unsigned>(result.packet.version),
                result.packet.tlvs.size());
    for (std::size_t i = 0; i < result.packet.tlvs.size(); ++i) {
        const wirecut::Tlv& tlv = result.packet.tlvs[i];
        std::printf("tlv[%zu] tag=%u len=%zu\n", i, static_cast<unsigned>(tlv.tag),
                    tlv.value.size());
    }
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::uint8_t> buf;
    if (argc >= 2) {
        std::ifstream file(argv[1], std::ios::binary);
        if (!file) {
            std::fprintf(stderr, "wirecut-parse: cannot open %s\n", argv[1]);
            return 2;
        }
        buf = read_all(file);
    } else {
        std::cin >> std::noskipws;
        buf = read_all(std::cin);
    }

    const wirecut::ParseResult result = wirecut::parse(buf);
    print_summary(buf, result);
    return result.ok() ? 0 : 1;
}
