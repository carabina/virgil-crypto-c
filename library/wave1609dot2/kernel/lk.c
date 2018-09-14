#include "lk.h"

void *calloc(size_t n, size_t size)
{
	printk(KERN_DEBUG "calloc >>>\n");
	return vzalloc(n * size);
}

void free(void *ptr)
{
    printk(KERN_DEBUG "<<< free\n");
	vfree(ptr);
}

void mbedtls_platform_zeroize( void *buf, size_t len )
{
    memset( buf, 0, len );
}

//#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PKCS1_V15)
int rand(void)
{
    printk(KERN_DEBUG "get_random_int\n");
	return get_random_int();
}
//#endif
