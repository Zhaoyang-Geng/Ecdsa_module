#include <linux/kernel.h>
#include <linux/module.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/module.h>
#include <linux/once.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <crypto/rng.h>
#include <crypto/drbg.h>
#include <crypto/akcipher.h>
#include <crypto/kpp.h>
#include <crypto/acompress.h>
#include <crypto/internal/cipher.h>
#include <crypto/internal/simd.h>
#include <linux/oid_registry.h>

#define XBUFSIZE 8

struct akcipher_testvec {
	const unsigned char *key;
	const unsigned char *params;
	const unsigned char *m;
	const unsigned char *c;
	unsigned int key_len;
	unsigned int param_len;
	unsigned int m_size;
	unsigned int c_size;
	bool public_key_vec;
	bool siggen_sigver_test;
	enum OID algo;
};

const struct akcipher_testvec vecs = {
	.key =
	"\x30\x5f\x02\x01\x01\x04\x18\x6f\xab\x03\x49\x34\xe4\xc0\xfc\x9a"
	"\xe6\x7f\x5b\x56\x59\xa9\xd7\xd1\xfe\xfd\x18\x7e\xe0\x9f\xd4\xa0"
	"\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x01\xa1\x34\x03\x32\x00"
	"\x04\xac\x2c\x77\xf5\x29\xf9\x16\x89\xfe\xa0\xea\x5e\xfe\xc7\xf2"
	"\x10\xd8\xee\xa0\xb9\xe0\x47\xed\x56\x3b\xc7\x23\xe5\x76\x70\xbd"
	"\x48\x87\xeb\xc7\x32\xc5\x23\x06\x3d\x0a\x7c\x95\x7b\xc9\x7c\x1c"
	"\x43",
	.key_len = 97,
	.m =
	"\x81\x51\x32\x5d\xcd\xba\xe9\xe0\xff\x95\xf9\xf9\x65\x84\x32\xdb"
	"\xed\xfd\xb2\x09",
	.m_size = 20,
	.algo = OID_id_ecdsa_with_sha1,
	.c =
	"\x30\x35\x02\x19\x00\x98\xc6\xbd\x12\xb2\x3e\xaf\x5e\x2a\x20\x45"
	"\x13\x20\x86\xbe\x3e\xb8\xeb\xd6\x2a\xbf\x66\x98\xff\x02\x18\x57"
	"\xa2\x2b\x07\xde\xa9\x53\x0f\x8d\xe9\x47\x1b\x1d\xc6\x62\x44\x72"
	"\xe8\xe2\x84\x4b\xc2\x5b\x64",
	.c_size = 55,
	.siggen_sigver_test = true,
	};

static void __testmgr_free_buf(char *buf[XBUFSIZE], int order)
{
	int i;

	for (i = 0; i < XBUFSIZE; i++)
		free_pages((unsigned long)buf[i], order);
}

static void testmgr_free_buf(char *buf[XBUFSIZE])
{
	__testmgr_free_buf(buf, 0);
}

static u8 *test_pack_u32(u8 *dst, u32 val)
{
	memcpy(dst, &val, sizeof(val));
	return dst + sizeof(val);
}

static int __testmgr_alloc_buf(char *buf[XBUFSIZE], int order)
{
	int i;

	for (i = 0; i < XBUFSIZE; i++) {
		buf[i] = (char *)__get_free_pages(GFP_KERNEL, order);
		if (!buf[i])
			goto err_free_buf;
	}

	return 0;

err_free_buf:
	while (i-- > 0)
		free_pages((unsigned long)buf[i], order);

	return -ENOMEM;
}

static int testmgr_alloc_buf(char *buf[XBUFSIZE])
{
	return __testmgr_alloc_buf(buf, 0);
}

static void hexdump(unsigned char *buf, unsigned int len)
{
	print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,
			16, 1,
			buf, len, false);
}

static int __init ecdsa_kernel_module_init(void)
{
	printk(KERN_INFO "Entering ecdsa_kernel_module\n");
	struct crypto_akcipher *tfm;
    char *xbuf[XBUFSIZE];
	struct akcipher_request *req;
	void *outbuf_enc = NULL;
	void *outbuf_dec = NULL;
	struct crypto_wait wait;
	unsigned int out_len_max, out_len = 0;
	int err = -ENOMEM;
	struct scatterlist src, dst, src_tab[3];
	const char *m, *c;
	unsigned int m_size, c_size;
	const char *op;
	u8 *key, *ptr;

	if (testmgr_alloc_buf(xbuf))
		return err;

	tfm = crypto_alloc_akcipher("ecdsa-nist-p192-generic", 0, 0);

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto free_xbuf;

	crypto_init_wait(&wait);

	key = kmalloc(vecs.key_len + sizeof(u32) * 2 + vecs.param_len,
		      GFP_KERNEL);
	if (!key)
		goto free_req;
	memcpy(key, vecs.key, vecs.key_len);
	ptr = key + vecs.key_len;
	ptr = test_pack_u32(ptr, vecs.algo);
	ptr = test_pack_u32(ptr, vecs.param_len);
	memcpy(ptr, vecs.params, vecs.param_len);

	if (vecs.public_key_vec)
		err = crypto_akcipher_set_pub_key(tfm, key, vecs.key_len);
	else
		err = crypto_akcipher_set_priv_key(tfm, key, vecs.key_len);
	if (err)
		goto free_key;

	/*
	 * First run test which do not require a private key, such as
	 * encrypt or verify.
	 */
	err = -ENOMEM;
	out_len_max = crypto_akcipher_maxsize(tfm);
	outbuf_enc = kzalloc(out_len_max, GFP_KERNEL);
	if (!outbuf_enc)
		goto free_key;

	if (!vecs.siggen_sigver_test) {
		m = vecs.m;
		m_size = vecs.m_size;
		c = vecs.c;
		c_size = vecs.c_size;
		op = "encrypt";
	} else {
		/* Swap args so we could keep plaintext (digest)
		 * in vecs.m, and cooked signature in vecs.c.
		 */
		m = vecs.c; /* signature */
		m_size = vecs.c_size;
		c = vecs.m; /* digest */
		c_size = vecs.m_size;
		op = "verify";
	}
	printk(KERN_INFO "OP: %s\n", op);

	err = -E2BIG;
	if (WARN_ON(m_size > PAGE_SIZE))
		goto free_all;
	memcpy(xbuf[0], m, m_size);

	sg_init_table(src_tab, 3);
	sg_set_buf(&src_tab[0], xbuf[0], 8);
	sg_set_buf(&src_tab[1], xbuf[0] + 8, m_size - 8);
	if (vecs.siggen_sigver_test) {
		if (WARN_ON(c_size > PAGE_SIZE))
			goto free_all;
		memcpy(xbuf[1], c, c_size);
		sg_set_buf(&src_tab[2], xbuf[1], c_size);
		akcipher_request_set_crypt(req, src_tab, NULL, m_size, c_size);
	} else {
		sg_init_one(&dst, outbuf_enc, out_len_max);
		akcipher_request_set_crypt(req, src_tab, &dst, m_size,
					   out_len_max);
	}
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);

	err = crypto_wait_req(vecs.siggen_sigver_test ?
			      /* Run asymmetric signature verification */
			      crypto_akcipher_verify(req) :
			      /* Run asymmetric encrypt */
			      crypto_akcipher_encrypt(req), &wait);
	if (err) {
		pr_err("alg: akcipher: %s test failed. err %d\n", op, err);
		goto free_all;
	}
	if (!vecs.siggen_sigver_test && c) {
		if (req->dst_len != c_size) {
			pr_err("alg: akcipher: %s test failed. Invalid output len\n",
			       op);
			err = -EINVAL;
			goto free_all;
		}
		/* verify that encrypted message is equal to expected */
		if (memcmp(c, outbuf_enc, c_size) != 0) {
			pr_err("alg: akcipher: %s test failed. Invalid output\n",
			       op);
			hexdump(outbuf_enc, c_size);
			err = -EINVAL;
			goto free_all;
		}
		else {
			printk(KERN_INFO "Output is correct\n");
			hexdump(outbuf_enc, c_size);
		}
	}

	/*
	 * Don't invoke (decrypt or sign) test which require a private key
	 * for vectors with only a public key.
	 */
	if (vecs.public_key_vec) {
		err = 0;
		goto free_all;
	}
	outbuf_dec = kzalloc(out_len_max, GFP_KERNEL);
	if (!outbuf_dec) {
		err = -ENOMEM;
		goto free_all;
	}

	if (!vecs.siggen_sigver_test && !c) {
		c = outbuf_enc;
		c_size = req->dst_len;
	}

	err = -E2BIG;
	op = vecs.siggen_sigver_test ? "sign" : "decrypt";
	if (WARN_ON(c_size > PAGE_SIZE))
		goto free_all;
	memcpy(xbuf[0], c, c_size);

	sg_init_one(&src, xbuf[0], c_size);
	sg_init_one(&dst, outbuf_dec, out_len_max);
	crypto_init_wait(&wait);
	akcipher_request_set_crypt(req, &src, &dst, c_size, out_len_max);

	err = crypto_wait_req(vecs.siggen_sigver_test ?
			      /* Run asymmetric signature generation */
			      crypto_akcipher_sign(req) :
			      /* Run asymmetric decrypt */
			      crypto_akcipher_decrypt(req), &wait);
	if (err) {
		pr_err("alg: akcipher: %s test failed. err %d\n", op, err);
		goto free_all;
	}
	out_len = req->dst_len;
	if (out_len < m_size) {
		pr_err("alg: akcipher: %s test failed. Invalid output len %u\n",
		       op, out_len);
		err = -EINVAL;
		goto free_all;
	}
	/* verify that decrypted message is equal to the original msg */
	if (memchr_inv(outbuf_dec, 0, out_len - m_size) ||
	    memcmp(m, outbuf_dec + out_len - m_size, m_size)) {
		pr_err("alg: akcipher: %s test failed. Invalid output\n", op);
		hexdump(outbuf_dec, out_len);
		err = -EINVAL;
	}
free_all:
	kfree(outbuf_dec);
	kfree(outbuf_enc);
free_key:
	kfree(key);
free_req:
	akcipher_request_free(req);
free_xbuf:
	testmgr_free_buf(xbuf);
	return err;
}

static void __exit ecdsa_kernel_module_exit(void)
{
    printk(KERN_INFO "Exiting ecdsa_kernel_module\n");
}

module_init(ecdsa_kernel_module_init);
module_exit(ecdsa_kernel_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhaoyang");
MODULE_DESCRIPTION("Kernel Crypto API Test");