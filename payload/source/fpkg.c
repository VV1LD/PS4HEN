#include <stddef.h>
#include <stdint.h>

#include "sections.h"
#include "sparse.h"
#include "freebsd_helper.h"
#include "sbl_helper.h"
#include "rif_helper.h"
#include "ccp_helper.h"
#include "pfs_helper.h"

typedef uint64_t vm_offset_t;

// real kernel hooks
extern void* (*real_malloc)(unsigned long size, void* type, int flags) PAYLOAD_DATA;
extern void (*real_free)(void* addr, void* type) PAYLOAD_DATA;
extern void (*real_dealloc)(void*) PAYLOAD_DATA;
extern void* (*real_memcpy)(void* dst, const void* src, size_t len) PAYLOAD_DATA;
extern void* (*real_memset)(void *s, int c, size_t n) PAYLOAD_DATA;
extern void* (*real_memcmp)(const void *b1, const void *b2, size_t len) PAYLOAD_DATA;
extern void (*real_printf)(const char* fmt, ...) PAYLOAD_DATA;
extern int (*real_sceSblServiceMailbox)(unsigned long service_id, uint8_t request[SBL_MSG_SERVICE_MAILBOX_MAX_SIZE], void* response) PAYLOAD_DATA;
extern int (*real_sceSblAuthMgrGetSelfInfo)(struct self_context* ctx, struct self_ex_info** info) PAYLOAD_DATA;
extern void (*real_sceSblAuthMgrSmStart)(void**) PAYLOAD_DATA;
extern int (*real_sceSblAuthMgrIsLoadable2)(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_DATA;
extern int (*real_sceSblAuthMgrVerifyHeader)(struct self_context* ctx) PAYLOAD_DATA;
 extern int (*real_fpu_kern_enter)(struct thread *td, struct fpu_kern_ctx *ctx, uint32_t flags) PAYLOAD_DATA;
extern int (*real_fpu_kern_leave)(struct thread *td, struct fpu_kern_ctx *ctx) PAYLOAD_DATA;
extern void (*real_Sha256Hmac)(uint8_t hash[0x20], const uint8_t* data, size_t data_size, const uint8_t* key, int key_size) PAYLOAD_DATA;
extern int (*real_AesCbcCfb128Decrypt)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv) PAYLOAD_DATA;
extern int (*real_sceSblPfsKeymgrGenEKpfsForGDGPAC)(struct pfs_key_blob* key_blob) PAYLOAD_DATA;
extern int (*real_RsaesPkcs1v15Dec2048CRT)(struct rsa_buffer* out, struct rsa_buffer* in, struct rsa_key* key) PAYLOAD_DATA;
extern int (*real_sceSblPfsSetKey)(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_DATA;
extern int (*real_sceSblServiceCryptAsync)(struct ccp_req* request) PAYLOAD_DATA;
extern int (*real_sceSblKeymgrSmCallfunc)(union keymgr_payload* payload) PAYLOAD_DATA;
extern int (*real_sx_xlock)(struct sx *sx, int opts) PAYLOAD_DATA;
extern int (*real_sx_xunlock)(struct sx *sx) PAYLOAD_DATA;

// our hooks for fpkg
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(union keymgr_payload* payload) PAYLOAD_CODE;
extern int my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl(struct pfs_key_blob* key_blob) PAYLOAD_CODE;
extern int my_sceSblPfsSetKey_pfs_sbl_init(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_CODE;
extern int my_sceSblServiceCryptAsync_pfs_crypto(struct ccp_req* request) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(union keymgr_payload* payload) PAYLOAD_CODE;

extern void* M_TEMP PAYLOAD_DATA;
extern const struct sbl_map_list_entry** sbl_driver_mapped_pages PAYLOAD_DATA; // here?

const struct sbl_key_rbtree_entry** sbl_keymgr_key_rbtree PAYLOAD_DATA;
void* fpu_ctx PAYLOAD_DATA;
struct fake_key_desc s_fake_keys[MAX_FAKE_KEYS] PAYLOAD_DATA;
struct sx s_fake_keys_lock PAYLOAD_DATA;


PAYLOAD_CODE static struct fake_key_desc* get_free_fake_key_slot(void) {

	struct fake_key_desc* slot = NULL;
	size_t i;


	real_sx_xlock(&s_fake_keys_lock,0);
	{

		for (i = 0; i < _countof(s_fake_keys); ++i) {
			if (!s_fake_keys[i].occupied) {
				s_fake_keys[i].occupied = 1;
				slot = s_fake_keys + i;
				break;
			}
		}
	}
	real_sx_xunlock(&s_fake_keys_lock);


	return slot;
}


PAYLOAD_CODE static inline struct sbl_key_rbtree_entry* sceSblKeymgrGetKey(unsigned int handle) {

struct sbl_key_rbtree_entry* entry = *sbl_keymgr_key_rbtree;


	while (entry) {
		if (entry->handle < handle)
			entry = entry->right;
		else if (entry->handle > handle)
			entry = entry->left;
		else if (entry->handle == handle)
			return entry;
	}


	return NULL;
}


PAYLOAD_CODE static struct fake_key_desc* is_fake_pfs_key(uint8_t* key) {

	struct fake_key_desc* slot = NULL;
	size_t i;




	real_sx_xlock(&s_fake_keys_lock,0);
	{

		for (i = 0; i < _countof(s_fake_keys); ++i) {
			if (!s_fake_keys[i].occupied)
				continue;

			if (real_memcmp(s_fake_keys[i].key, key, sizeof(s_fake_keys[i].key)) == 0) {
				slot = s_fake_keys + i;
				break;
			}
		}
	}
	real_sx_xunlock(&s_fake_keys_lock);


	return slot;
}



// a common function to generate a final key for PFS
PAYLOAD_CODE inline void pfs_gen_crypto_key(uint8_t* ekpfs, uint8_t seed[PFS_SEED_SIZE], unsigned int index, uint8_t key[PFS_FINAL_KEY_SIZE]) {

	struct thread* td = curthread();

	uint8_t d[4 + PFS_SEED_SIZE];

	real_memset(d, 0, sizeof(d));

	// an index tells which key we should generate 
	*(uint32_t*)d = (uint32_t)(index);
	real_memcpy(d + sizeof(uint32_t), seed, PFS_SEED_SIZE);

	real_fpu_kern_enter(td, fpu_ctx,0);
	{


		real_Sha256Hmac(key, d, sizeof(d), ekpfs, EKPFS_SIZE);

	}
	real_fpu_kern_leave(td, fpu_ctx);

}

// an encryption key generator based on EKPFS and PFS header seed 
PAYLOAD_CODE inline void pfs_generate_enc_key(uint8_t* ekpfs, uint8_t seed[PFS_SEED_SIZE], uint8_t key[PFS_FINAL_KEY_SIZE]) {

	pfs_gen_crypto_key(ekpfs, seed, 1, key);

}

//  asigning key generator based on EKPFS and PFS header seed 
PAYLOAD_CODE inline void pfs_generate_sign_key(uint8_t* ekpfs, uint8_t seed[PFS_SEED_SIZE], uint8_t key[PFS_FINAL_KEY_SIZE]) {

	pfs_gen_crypto_key(ekpfs, seed, 2, key);
}

PAYLOAD_CODE inline int my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl(struct pfs_key_blob* blob) {


	struct thread* td = curthread();

	struct rsa_buffer in_data;
	struct rsa_buffer out_data;
	struct rsa_key key;
	uint8_t dec_data[EEKPFS_SIZE];
	struct fake_key_desc* fake_key_slot;
	uint8_t outTest[0x500];
	int ret;

	


	

	// try to decrypt EEKPFS normally 

	ret = real_sceSblPfsKeymgrGenEKpfsForGDGPAC(blob);


	if (ret) {



		// if this key is for debug/fake content, we could try to decrypt it manually 
		if (!blob->finalized) {

			real_memset(&in_data, 0, sizeof(in_data));
			{
				in_data.ptr = blob->eekpfs;
				in_data.size = sizeof(blob->eekpfs);
			}

			real_memset(&out_data, 0, sizeof(out_data));
			{
				out_data.ptr = dec_data;
				out_data.size = sizeof(dec_data);
			}

			real_memset(&key, 0, sizeof(key));
			{
				// here we feed a custom key to the algorithm 
				key.p = (uint8_t*)s_ypkg_p;
				key.q = (uint8_t*)s_ypkg_q;
				key.dmp1 = (uint8_t*)s_ypkg_dmp1;
				key.dmq1 = (uint8_t*)s_ypkg_dmq1;
				key.iqmp = (uint8_t*)s_ypkg_iqmp;
			}

			real_fpu_kern_enter(td, fpu_ctx,0);
			{
				ret = real_RsaesPkcs1v15Dec2048CRT(&out_data, &in_data, &key);
			}
			real_fpu_kern_leave(td, fpu_ctx);

			if (ret == 0) { // got EKPFS key? 
				real_memcpy(blob->ekpfs, dec_data, sizeof(blob->ekpfs));

				// add it to our key list 
				fake_key_slot = get_free_fake_key_slot();
				if (fake_key_slot)
					real_memcpy(fake_key_slot->key, blob->ekpfs, sizeof(fake_key_slot->key));
			}
		}
	}
	return ret;
}

PAYLOAD_CODE int my_sceSblPfsSetKey_pfs_sbl_init(unsigned int* ekh, unsigned int* skh, uint8_t* key, uint8_t* iv, int mode, int unused, uint8_t disc_flag) {

	struct sbl_key_rbtree_entry* key_entry;
	int is_fake_key;
	int ret;

	ret = real_sceSblPfsSetKey(ekh, skh, key, iv, mode, unused, disc_flag);

	// check if it's a key that we have decrypted manually 
	is_fake_key = is_fake_pfs_key(key) != NULL;

	key_entry = sceSblKeymgrGetKey(*ekh); // find a corresponding key entry 
	if (key_entry) {
		if (is_fake_key) {
			// generate an encryption key 
			pfs_generate_enc_key(key, iv, key_entry->desc.pfs.key);
			real_memcpy(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(s_fake_key_seed));
		}
	}
	key_entry = sceSblKeymgrGetKey(*skh); // find a corresponding key entry 
	if (key_entry) {
		if (is_fake_key) {
			// generate a signing key
			pfs_generate_sign_key(key, iv, key_entry->desc.pfs.key);
			real_memcpy(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(s_fake_key_seed));
		}
	}
	return ret;
}

PAYLOAD_CODE inline int npdrm_decrypt_debug_rif(unsigned int type, uint8_t* data) {

	struct thread* td = curthread();

	int ret;

	real_fpu_kern_enter(td, fpu_ctx,0);
	{
		// decrypt fake rif manually using a key from publishing tools 
		ret = real_AesCbcCfb128Decrypt(data + RIF_DIGEST_SIZE, data + RIF_DIGEST_SIZE, RIF_DATA_SIZE, rif_debug_key, sizeof(rif_debug_key) * 8, data);

		if (ret)
			ret = SCE_SBL_ERROR_NPDRM_ENOTSUP;
	}
	real_fpu_kern_leave(td, fpu_ctx);

	return ret;
}

PAYLOAD_CODE static inline const struct sbl_map_list_entry* sceSblDriverFindMappedPageListByGpuVa(vm_offset_t gpu_va)
{

  const struct sbl_map_list_entry* entry;
  if (!gpu_va)
  {
    return NULL;
  }
  entry = *sbl_driver_mapped_pages;
  while (entry)
  {
    if (entry->gpu_va == gpu_va)
    {
      return entry;
    }
    entry = entry->next;
  }
  return NULL;
}


PAYLOAD_CODE static inline vm_offset_t sceSblDriverGpuVaToCpuVa(vm_offset_t gpu_va, size_t* num_page_groups)
{

  const struct sbl_map_list_entry* entry = sceSblDriverFindMappedPageListByGpuVa(gpu_va);
  if (!entry)
  {
    return 0;
  }
  if (num_page_groups)
  {
    *num_page_groups = entry->num_page_groups;
  }
  return entry->cpu_va;
}


PAYLOAD_CODE int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(union keymgr_payload* payload) {
	uint64_t buf_gpu_va = (uint64_t)payload->mapped_buf;

	// it's SM request, thus we have the GPU address here, so we need to convert it to the CPU address 
	union keymgr_request* request = (union keymgr_request*)sceSblDriverGpuVaToCpuVa(buf_gpu_va, NULL);
	union keymgr_response* response = (union keymgr_response*)request;
	struct ekc* eekc;
	int orig_ret, ret;

	// try to decrypt rif normally 
	ret = orig_ret = real_sceSblKeymgrSmCallfunc(payload);


	// and if it fails then we check if it's fake rif and try to decrypt it by ourselves
	if ((ret != 0 || payload->status != 0) && request) {
		//if (BE16(request->decrypt_entire_rif.rif.format) != 0x200) { // not fake? 
		if (request->decrypt_entire_rif.rif.format != 2) { // not fake? 
			ret = orig_ret;
			goto err;
		}

		ret = npdrm_decrypt_debug_rif(request->decrypt_entire_rif.rif.format, request->decrypt_entire_rif.rif.digest);

		if (ret) {
			ret = orig_ret;
			goto err;
		}

		// XXX: sorry, i'm lazy to refactor this crappy code :D basically, we're copying decrypted data to proper place,
		 //  consult with kernel code if offsets needs to be changed 
		real_memcpy(response->decrypt_entire_rif.raw, request->decrypt_entire_rif.rif.digest, sizeof(request->decrypt_entire_rif.rif.digest) + sizeof(request->decrypt_entire_rif.rif.data));


		real_memset(response->decrypt_entire_rif.raw + 
				sizeof(request->decrypt_entire_rif.rif.digest) +
				sizeof(request->decrypt_entire_rif.rif.data), 
				0,
				sizeof(response->decrypt_entire_rif.raw) - 
				(sizeof(request->decrypt_entire_rif.rif.digest) + 
				sizeof(request->decrypt_entire_rif.rif.data)));

		payload->status = ret;
		ret = 0;
	}


err:
	return ret;
}


PAYLOAD_CODE int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(union keymgr_payload* payload) {

	// it's SM request, thus we have the GPU address here, so we need to convert it to the CPU address
	union keymgr_request* request = (union keymgr_request*)sceSblDriverGpuVaToCpuVa(payload->mapped_buf, NULL);
	int ret;
	
	
	// try to decrypt rif normally 
	ret = real_sceSblKeymgrSmCallfunc(payload);

	// and if it fails then we check if it's fake rif and try to decrypt it by ourselves 
	if ((ret != 0 || payload->status != 0) && request) {

		if (request->decrypt_rif.type == 0x200) { // fake?
			ret = npdrm_decrypt_debug_rif(request->decrypt_rif.type, request->decrypt_rif.data);
			payload->status = ret;
			ret = 0;
		}
	}

	return ret;
}

PAYLOAD_CODE int ccp_msg_populate_key(unsigned int key_handle, uint8_t* key, int reverse) {

	struct sbl_key_rbtree_entry* key_entry;
	uint8_t* in_key;
	int i;
	int status = 0;

	// searching for a key entry 
	key_entry = sceSblKeymgrGetKey(key_handle);

	if (key_entry) {
		// we have found one, now checking if it's our key 
		if (real_memcmp(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(key_entry->desc.pfs.seed)) == 0) {
			// currently we have a crypto request that use a key slot which should be already in CCP, but because we
			// did everything manually, we don't have this key slot, so we need to remove using of key slot and place
			// a plain key here 

			in_key = key_entry->desc.pfs.key;
			if (reverse) { // reverse bytes of a key if it's needed 

				for (i = 0; i < 0x20; ++i)
					key[0x20 - i - 1] = in_key[i];
			} else { // copy a key as is 

				real_memcpy(key, in_key, 0x20);
			}
			status = 1;
		}
	}

	return status;
}

PAYLOAD_CODE int ccp_msg_populate_key_if_needed(struct ccp_msg* msg) {

	unsigned int cmd = msg->op.common.cmd; 
	unsigned int type = CCP_OP(cmd);
	uint8_t* buf;
	int status = 0;


	// skip messages that use plain keys and key slots 
	if (!(cmd & CCP_USE_KEY_HANDLE))
		goto skip;

	buf = (uint8_t*)&msg->op;

	// we only need to handle xts/hmac crypto operations 
	switch (type) {
		case CCP_OP_XTS:
			status = ccp_msg_populate_key(*(uint32_t*)(buf + 0x28), buf + 0x28, 1); // xts key have a reversed byte order 
			break;

		case CCP_OP_HMAC:
			status = ccp_msg_populate_key(*(uint32_t*)(buf + 0x40), buf + 0x40, 0); // hmac key have a normal byte order 
			break;

		default:
			goto skip;
	}

	// if key was successfully populated, then remove the flag which tells CCP to use a key slot 
	if (status)
		msg->op.common.cmd &= ~CCP_USE_KEY_HANDLE;

skip:
	return status;
}

PAYLOAD_CODE int my_sceSblServiceCryptAsync_pfs_crypto(struct ccp_req* request) {

	struct ccp_msg* msg;
	int ret;

	TAILQ_FOREACH(msg, &request->msgs, next){
		// handle each message in crypto request 
		ccp_msg_populate_key_if_needed(msg);
	}

	// run a crypto function normally 
	ret = real_sceSblServiceCryptAsync(request);

	return ret;
}

