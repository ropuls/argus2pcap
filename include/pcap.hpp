#pragma once

#include <cstdio>
#include <ctime>
#include "file.hpp"
#include <system_error>

#ifndef __linux__
struct timeval {
        long    tv_sec;         /* seconds */
        long    tv_usec;        /* and microseconds */
};
#endif

class eyesdn {
public:
    eyesdn() = default;

    eyesdn(const char *fname) :
        m_file(fname, "wb")
    {
        if (!m_file) {
            throw std::system_error(errno, std::system_category(), fname);
        }
        write_header();
    }

    void write_trace(struct timeval tv, const unsigned char *buffer, size_t size, bool is_network);
protected:
    void write_header() {
        static const char magic[] = "EyeSDN";

        m_file.write(magic, sizeof(magic));
    }

protected:
    file m_file;
};

#pragma pack(push, 1)
typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t; // 32+16+16+32+32+32+32 = 6*32 = 196/8 = 24 bytes

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t; // => 16 bytes


typedef struct isdn_hdr_s {
        uint16_t packet_type; // 2
        uint16_t arphdr_type; // 2  4
        uint16_t lladdr_len;  // 2  6
        uint64_t ll_addr;     // 8  14
        uint8_t proto_type[2];  // 2  16
                                                        // payload
} isdn_hdr_t; //
#pragma pack(pop)




