// SPDX-License-Identifier: MIT
// Copyright (c) 2025 smae
//
// Tiny assert-based runner (no network, no third-party fetch).

#include "wirecut/parser.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

int g_passed = 0;
int g_failed = 0;

void check(bool cond, const char* expr, const char* file, int line) {
    if (cond) {
        ++g_passed;
        return;
    }
    std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expr);
    ++g_failed;
}

#define CHECK(expr) check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)

#define CHECK_EQ(a, b)                                                                           \
    do {                                                                                         \
        const auto _va = (a);                                                                    \
        const auto _vb = (b);                                                                    \
        if (_va == _vb) {                                                                        \
            ++g_passed;                                                                          \
        } else {                                                                                 \
            std::fprintf(stderr, "FAIL %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b);          \
            ++g_failed;                                                                          \
        }                                                                                        \
    } while (0)

std::vector<std::uint8_t> header(std::uint8_t version, std::uint8_t n_tlvs) {
    return {0x57, 0x43, 0x54, 0x31, version, n_tlvs};
}

void append_tlv(std::vector<std::uint8_t>& frame, std::uint8_t tag,
                const std::vector<std::uint8_t>& value) {
    frame.push_back(tag);
    const std::uint16_t length = static_cast<std::uint16_t>(value.size());
    frame.push_back(static_cast<std::uint8_t>((length >> 8) & 0xff));
    frame.push_back(static_cast<std::uint8_t>(length & 0xff));
    frame.insert(frame.end(), value.begin(), value.end());
}

void append_tlv_raw_len(std::vector<std::uint8_t>& frame, std::uint8_t tag, std::uint16_t length,
                        const std::vector<std::uint8_t>& value) {
    frame.push_back(tag);
    frame.push_back(static_cast<std::uint8_t>((length >> 8) & 0xff));
    frame.push_back(static_cast<std::uint8_t>(length & 0xff));
    frame.insert(frame.end(), value.begin(), value.end());
}

void test_valid_frame() {
    auto frame = header(1, 1);
    append_tlv(frame, 0x10, {0xde, 0xad, 0xbe, 0xef});
    const wirecut::ParseResult result = wirecut::parse(frame);
    CHECK(result.ok());
    CHECK_EQ(result.packet.version, 1);
    CHECK_EQ(result.packet.tlvs.size(), 1u);
    CHECK_EQ(result.packet.tlvs[0].tag, 0x10);
    CHECK_EQ(result.packet.tlvs[0].value.size(), 4u);
    CHECK_EQ(result.packet.tlvs[0].value[0], 0xde);
    CHECK_EQ(result.packet.tlvs[0].value[3], 0xef);
}

void test_empty_tlv_list() {
    const auto frame = header(1, 0);
    const wirecut::ParseResult result = wirecut::parse(frame);
    CHECK(result.ok());
    CHECK_EQ(result.packet.tlvs.size(), 0u);
    CHECK_EQ(std::string(wirecut::status_string(result.status)), "ok");
}

void test_multiple_tlvs() {
    auto frame = header(1, 3);
    append_tlv(frame, 0x01, {0x11});
    append_tlv(frame, 0x02, {});
    append_tlv(frame, 0x03, {0x21, 0x22, 0x23});
    const wirecut::ParseResult result = wirecut::parse(frame);
    CHECK(result.ok());
    CHECK_EQ(result.packet.tlvs.size(), 3u);
    CHECK_EQ(result.packet.tlvs[0].tag, 0x01);
    CHECK_EQ(result.packet.tlvs[1].tag, 0x02);
    CHECK_EQ(result.packet.tlvs[1].value.size(), 0u);
    CHECK_EQ(result.packet.tlvs[2].value.size(), 3u);
}

void test_truncated_header() {
    const std::vector<std::uint8_t> empty;
    CHECK_EQ(wirecut::parse(empty).status, wirecut::ParseStatus::Truncated);
    CHECK_EQ(wirecut::parse(nullptr, 0).status, wirecut::ParseStatus::Truncated);
    CHECK_EQ(wirecut::parse(nullptr, 10).status, wirecut::ParseStatus::Truncated);

    const std::vector<std::uint8_t> short_magic = {0x57, 0x43, 0x54};
    CHECK_EQ(wirecut::parse(short_magic).status, wirecut::ParseStatus::Truncated);

    const std::vector<std::uint8_t> no_count = {0x57, 0x43, 0x54, 0x31, 0x01};
    CHECK_EQ(wirecut::parse(no_count).status, wirecut::ParseStatus::Truncated);
    CHECK_EQ(std::string(wirecut::status_string(wirecut::ParseStatus::Truncated)), "truncated");
}

void test_truncated_value() {
    auto frame = header(1, 1);
    frame.push_back(0x07);
    frame.push_back(0x00);
    // Claim length 4 but only 2 header bytes of the TLV exist (no value bytes, and
    // the length field itself is truncated).
    CHECK_EQ(wirecut::parse(frame).status, wirecut::ParseStatus::Truncated);

    auto almost = header(1, 1);
    almost.push_back(0x07);
    almost.push_back(0x00); // high byte of length
    CHECK_EQ(wirecut::parse(almost).status, wirecut::ParseStatus::Truncated);
}

void test_length_overflow() {
    auto frame = header(1, 1);
    append_tlv_raw_len(frame, 0x01, 0x0100, {0xaa, 0xbb, 0xcc, 0xdd});
    const wirecut::ParseResult result = wirecut::parse(frame);
    CHECK_EQ(result.status, wirecut::ParseStatus::LengthOverflow);
    CHECK_EQ(std::string(wirecut::status_string(result.status)), "length_overflow");
}

void test_bad_magic() {
    auto frame = header(1, 0);
    frame[0] = 0x58;
    CHECK_EQ(wirecut::parse(frame).status, wirecut::ParseStatus::BadMagic);

    frame = header(1, 0);
    frame[3] = 0x32;
    CHECK_EQ(wirecut::parse(frame).status, wirecut::ParseStatus::BadMagic);
    CHECK_EQ(std::string(wirecut::status_string(wirecut::ParseStatus::BadMagic)), "bad_magic");
}

void test_bad_version() {
    CHECK_EQ(wirecut::parse(header(0, 0)).status, wirecut::ParseStatus::BadVersion);
    CHECK_EQ(wirecut::parse(header(2, 0)).status, wirecut::ParseStatus::BadVersion);
    CHECK_EQ(std::string(wirecut::status_string(wirecut::ParseStatus::BadVersion)), "bad_version");
}

void test_max_size() {
    std::vector<std::uint8_t> frame(wirecut::kMaxFrameSize, 0);
    frame[0] = 0x57;
    frame[1] = 0x43;
    frame[2] = 0x54;
    frame[3] = 0x31;
    frame[4] = 1;
    frame[5] = 1;
    frame[6] = 0xaa;
    const std::uint16_t value_len =
        static_cast<std::uint16_t>(wirecut::kMaxFrameSize - 9); // 4087 = 0x0FF7
    frame[7] = static_cast<std::uint8_t>((value_len >> 8) & 0xff);
    frame[8] = static_cast<std::uint8_t>(value_len & 0xff);

    const wirecut::ParseResult ok = wirecut::parse(frame);
    CHECK(ok.ok());
    CHECK_EQ(ok.packet.tlvs.size(), 1u);
    CHECK_EQ(ok.packet.tlvs[0].value.size(), static_cast<std::size_t>(value_len));

    std::vector<std::uint8_t> oversize = frame;
    oversize.push_back(0x00);
    const wirecut::ParseResult too_big = wirecut::parse(oversize);
    CHECK_EQ(too_big.status, wirecut::ParseStatus::Oversize);
    CHECK_EQ(std::string(wirecut::status_string(too_big.status)), "oversize");
}

void test_n_tlvs_vs_remaining() {
    // n_tlvs=2 but no TLV bytes follow the header.
    CHECK_EQ(wirecut::parse(header(1, 2)).status, wirecut::ParseStatus::TlvCountMismatch);

    // n_tlvs=2 but only one complete TLV is present.
    auto one_of_two = header(1, 2);
    append_tlv(one_of_two, 0x01, {0x42});
    CHECK_EQ(wirecut::parse(one_of_two).status, wirecut::ParseStatus::TlvCountMismatch);

    // n_tlvs=255 with only a header.
    CHECK_EQ(wirecut::parse(header(1, 255)).status, wirecut::ParseStatus::TlvCountMismatch);
    CHECK_EQ(std::string(wirecut::status_string(wirecut::ParseStatus::TlvCountMismatch)),
             "tlv_count_mismatch");
}

void test_status_string_unknown() {
    CHECK_EQ(std::string(wirecut::status_string(static_cast<wirecut::ParseStatus>(99))),
             "unknown");
}

void test_vector_overload() {
    const std::vector<std::uint8_t> frame = header(1, 0);
    CHECK(wirecut::parse(frame).ok());
}

} // namespace

int main() {
    test_valid_frame();
    test_empty_tlv_list();
    test_multiple_tlvs();
    test_truncated_header();
    test_truncated_value();
    test_length_overflow();
    test_bad_magic();
    test_bad_version();
    test_max_size();
    test_n_tlvs_vs_remaining();
    test_status_string_unknown();
    test_vector_overload();

    std::printf("%d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
