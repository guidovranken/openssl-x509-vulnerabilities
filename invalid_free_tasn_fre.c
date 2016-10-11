#include <openssl/x509.h>
#include <openssl/bio.h>
#include <string.h>
int main(void)
{
    unsigned char* buf = NULL;
    const unsigned char *p;
    unsigned char data[] = {
          0x30, 0x80, 0x30, 0x00
    };
    buf = malloc(sizeof(data));
    if ( buf == NULL ) {
        return 0;
    }
    memcpy(buf, data, sizeof(data));
    p = buf;

    X509 *x509 = d2i_X509(NULL, &p, sizeof(data));
    if ( x509 != NULL ) {
        X509_free(x509);
    }

    free(buf);
    return 0;
}
