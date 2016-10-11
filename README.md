# openssl-x509-vulnerabilities

These programs will run just fine, unless any of the following events occur.

## invalid_free_tasn_fre.c

This will invoke ```asn1_item_embed_new```.

(Copied from OpenSSL 1.1.0b sources)

```c
int asn1_item_embed_new(ASN1_VALUE **pval, const ASN1_ITEM *it, int embed)
{
    ...
    ...
    case ASN1_ITYPE_NDEF_SEQUENCE:
    case ASN1_ITYPE_SEQUENCE:
        if (asn1_cb) {
            i = asn1_cb(ASN1_OP_NEW_PRE, pval, it, NULL);
            if (!i)
                goto auxerr;
            if (i == 2) {
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
                OPENSSL_mem_debug_pop();
#endif
                return 1;
            }
        }
        if (embed) {
            memset(*pval, 0, it->size);
        } else {
            *pval = OPENSSL_zalloc(it->size);
            if (*pval == NULL)
                goto memerr;
        }
        /* 0 : init. lock */
        if (asn1_do_lock(pval, 0, it) < 0)
            goto memerr;
        asn1_enc_init(pval, it);
        for (i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
            pseqval = asn1_get_field_ptr(pval, tt);
            if (!asn1_template_new(pseqval, tt))
                goto memerr;
        }
        if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it, NULL))
            goto auxerr;
        break;
    ...
    ...
}
```

If this code fails to allocate memory (```OPENSSL_zalloc```) or to acquire a lock (```asn1_do_lock```), an invalid free will occur.

For an easy demonstration of the vulnerability you may alter ```CRYPTO_THREAD_lock_new()``` so that it always indicates failure.

```c
CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void)
{
    return NULL;
}
```

```sh
$ ./a.out 
*** Error in `./a.out': free(): invalid pointer: 0x00000000013d50c8 ***
Aborted
```
