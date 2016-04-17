#include <unistd.h>
#include <arpa/inet.h>

/* from RFC 4880 section 6.1 */
#define CRC24_INIT 0xB704CEL
#define CRC24_POLY 0x1864CFBL

typedef long crc24;
crc24 crc_octets(unsigned char *octets, size_t len)
{
    crc24 crc = CRC24_INIT;
    int i;
    while (len--) {
        crc ^= (*octets++) << 16;
        for (i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= CRC24_POLY;
        }
    }
    return crc & 0xFFFFFFL;
}


int main()
{
    crc24 output;
    int i = 0;
    unsigned char o;
    unsigned char indata[100000];
    ssize_t rr = read(0, indata, sizeof(indata));
    if (rr <= 0)
        return 1;
    output = crc_octets(indata, rr);
    for (i = 2; i >= 0; i--) {
        o = ((output >> (8 * i)) & 0xff);
        write(1, &o, sizeof(o));
    }
    return 0;
}
