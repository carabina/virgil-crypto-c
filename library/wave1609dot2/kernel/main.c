#include <linux/kernel.h>
#include <linux/module.h>

#include "mbedtls/sha256.h" /* SHA-256 only */
#include "mbedtls/md.h"     /* generic interface */

#include "mbedtls/base64.h"
#include "mbedtls/version.h"

MODULE_LICENSE("GPLv2");

static void print_hex(const char *title, const unsigned char buf[], size_t len)
{
    size_t i;
    printk("%s: ", title);

    for (i = 0; i < len; i++)
        printk("%02x", buf[i]);

    printk("\r\n");
}

void mbedtls_version_get_string( char *string );

static int mod_init(void)
{
	unsigned char version[32];
	unsigned char hash[32];	// SHA-256 outputs 32 bytes

    static const char test_data[] = "Hello, world !";

    // Get MbedTLS version
    mbedtls_version_get_string_full(version);
    printk("VIRGIL: mbedtls version is %s\n", version);

    // Test hash
    mbedtls_sha256(test_data, strlen(test_data), hash, 0);
    print_hex("SHA256", hash, sizeof(hash));

	return -EINVAL;
}

static void mod_exit(void)
{
}

module_init(mod_init);
module_exit(mod_exit);
