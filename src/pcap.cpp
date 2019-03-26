#include "pcap.hpp"

#include <sys/time.h>

void write_esc (FILE *file, const unsigned char *buf, int len) {
    int i, byte;

    for (i = 0; i < len; ++i) {
        byte = buf[i];
        if (byte == 0xff || byte == 0xfe) {
            fputc(0xfe, file);
            byte -= 2;
        }
        fputc(byte, file);
    }

    if (ferror(file)) {
        fprintf(stderr, "Error on writing to file!\nAborting...\n");
    }
}



void eyesdn::write_trace(struct timeval tv, const unsigned char *buffer, size_t size, bool is_network) {
    unsigned char head[12];

    int len = size;

    // deviceB is network side by definition
    unsigned char origin = is_network ? 0 : 1;

    FILE* f = m_file;

    fputc(0xff, f);
    head[0] = (unsigned char)(0xff & (tv.tv_usec >> 16));
    head[1] = (unsigned char)(0xff & (tv.tv_usec >> 8));
    head[2] = (unsigned char)(0xff & tv.tv_usec);
    head[3] = (unsigned char)0;
    head[4] = (unsigned char)(0xff & (tv.tv_sec >> 24));
    head[5] = (unsigned char)(0xff & (tv.tv_sec >> 16));
    head[6] = (unsigned char)(0xff & (tv.tv_sec >> 8));
    head[7] = (unsigned char)(0xff & tv.tv_sec);
    head[8] = (unsigned char) 0;
    head[9] = (unsigned char) origin;
    head[10]= (unsigned char)(0xff & (len >> 8));
    head[11]= (unsigned char)(0xff & len);

    write_esc(f, head, sizeof(head));
    write_esc(f, buffer, size);
    fflush(f);
}

