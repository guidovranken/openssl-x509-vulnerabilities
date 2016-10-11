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

## aa

This will invoke ```x509_name_ex_d2i```.

(Copied from OpenSSL 1.1.0b sources)

```c
static int x509_name_ex_d2i(ASN1_VALUE **val,
                            const unsigned char **in, long len,
                            const ASN1_ITEM *it, int tag, int aclass,
                            char opt, ASN1_TLC *ctx)
{
    ...
    ...

    /* Convert internal representation to X509_NAME structure */
    for (i = 0; i < sk_STACK_OF_X509_NAME_ENTRY_num(intname.s); i++) {
        entries = sk_STACK_OF_X509_NAME_ENTRY_value(intname.s, i);
        for (j = 0; j < sk_X509_NAME_ENTRY_num(entries); j++) {
            entry = sk_X509_NAME_ENTRY_value(entries, j);
            entry->set = i;
            if (!sk_X509_NAME_ENTRY_push(nm.x->entries, entry)) {
                /*
                 * Free all in entries if sk_X509_NAME_ENTRY_push return failure.
                 * X509_NAME_ENTRY_free will check the null entry.
                 */
                sk_X509_NAME_ENTRY_pop_free(entries, X509_NAME_ENTRY_free);
                goto err;
            }
            /*
             * If sk_X509_NAME_ENTRY_push return success, clean the entries[j].
             * It's necessary when 'goto err;' happens.
             */
            sk_X509_NAME_ENTRY_set(entries, j, NULL);
        }
        sk_X509_NAME_ENTRY_free(entries);
        sk_STACK_OF_X509_NAME_ENTRY_set(intname.s, i, NULL);
    }
    ...
    ...
 err:
    X509_NAME_free(nm.x);
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname.s, sk_X509_NAME_ENTRY_free);
    ASN1err(ASN1_F_X509_NAME_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
    return 0;
}
```

If ```sk_X509_NAME_ENTRY_push``` fails due to a failure to reallocate memory, a double-free will occur; the first free occurs in ```sk_X509_NAME_ENTRY_pop_free``` and the second in ```sk_STACK_OF_X509_NAME_ENTRY_pop_free```.

For an easy demonstration of the vulnerability you may do the following in order to emulate failure. Change

```c
            if (!sk_X509_NAME_ENTRY_push(nm.x->entries, entry)) {
```

into

```c
            if ( 1 ) {
```

```sh
$ ./a.out 
Segmentation fault
```
