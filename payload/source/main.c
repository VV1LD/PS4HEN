#include <stddef.h>
#include <stdint.h>

#include "sections.h"
#include "sparse.h"
#include "freebsd_helper.h"
#include "elf_helper.h"
#include "self_helper.h"
#include "sbl_helper.h"
#include "pfs_helper.h"

typedef uint64_t vm_offset_t;

// real kernel hooks
void* M_TEMP PAYLOAD_DATA;
void* (*real_malloc)(unsigned long size, void* type, int flags) PAYLOAD_DATA;
void (*real_free)(void* addr, void* type) PAYLOAD_DATA;
void (*real_dealloc)(void*) PAYLOAD_DATA;
void* (*real_memcpy)(void* dst, const void* src, size_t len) PAYLOAD_DATA;
void (*real_printf)(const char* fmt, ...) PAYLOAD_DATA;
int (*real_sceSblServiceMailbox)(unsigned long service_id, uint8_t request[SBL_MSG_SERVICE_MAILBOX_MAX_SIZE], void* response) PAYLOAD_DATA;
int (*real_sceSblAuthMgrGetSelfInfo)(struct self_context* ctx, struct self_ex_info** info) PAYLOAD_DATA;
void (*real_sceSblAuthMgrSmStart)(void**) PAYLOAD_DATA;
int (*real_sceSblAuthMgrIsLoadable2)(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_DATA;
int (*real_sceSblAuthMgrVerifyHeader)(struct self_context* ctx) PAYLOAD_DATA;
int (*real_fpu_kern_enter)(struct thread *td, struct fpu_kern_ctx *ctx, uint32_t flags) PAYLOAD_DATA;
int (*real_fpu_kern_leave)(struct thread *td, struct fpu_kern_ctx *ctx) PAYLOAD_DATA;
void (*real_Sha256Hmac)(uint8_t hash[0x20], const uint8_t* data, size_t data_size, const uint8_t* key, int key_size) PAYLOAD_DATA;
int (*real_AesCbcCfb128Decrypt)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv) PAYLOAD_DATA;
int (*real_sceSblPfsKeymgrGenEKpfsForGDGPAC)(struct pfs_key_blob* key_blob) PAYLOAD_DATA;
int (*real_RsaesPkcs1v15Dec2048CRT)(struct rsa_buffer* out, struct rsa_buffer* in, struct rsa_key* key) PAYLOAD_DATA;
int (*real_sceSblPfsSetKey)(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_DATA;
int (*real_sceSblServiceCryptAsync)(struct ccp_req* request) PAYLOAD_DATA;
int (*real_sceSblKeymgrSmCallfunc)(union keymgr_payload* payload) PAYLOAD_DATA;
int (*real_sx_xlock)(struct sx *sx, int opts) PAYLOAD_DATA;
int (*real_sx_xunlock)(struct sx *sx) PAYLOAD_DATA;
void* (*real_memcmp)(const void *b1, const void *b2, size_t len) PAYLOAD_DATA;
void* (*real_memset)(void *s, int c, size_t n) PAYLOAD_DATA;
void* (*real_eventhandler_register)(void* list, const char* name, void* func, void* arg, int priority) PAYLOAD_DATA;
void  (*real_sx_destroy)(struct sx *sx) PAYLOAD_DATA;
void  (*real_sx_init_flags)(struct sx *sx, const char *description, int opts) PAYLOAD_DATA;

// our hooks
extern int my_sceSblAuthMgrIsLoadable2(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_CODE;
extern int my_sceSblAuthMgrVerifyHeader(struct self_context* ctx) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(union keymgr_payload* payload) PAYLOAD_CODE;
extern int my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl(struct pfs_key_blob* key_blob) PAYLOAD_CODE;
extern int my_sceSblPfsSetKey_pfs_sbl_init(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_CODE;
extern int my_sceSblServiceCryptAsync_pfs_crypto(struct ccp_req* request) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(union keymgr_payload* payload) PAYLOAD_CODE;

int (*npdrm_decrypt_rif_new)( int integer, struct rif_key_blob* key_blob, struct rif* rif) PAYLOAD_DATA;

extern const struct sbl_map_list_entry** sbl_driver_mapped_pages PAYLOAD_DATA; 
extern const uint8_t* mini_syscore_self_binary PAYLOAD_DATA;
extern const struct sbl_key_rbtree_entry** sbl_keymgr_key_rbtree PAYLOAD_DATA;
extern void* fpu_ctx PAYLOAD_DATA;

extern struct fake_key_desc s_fake_keys[MAX_FAKE_KEYS] PAYLOAD_DATA;
extern struct sx s_fake_keys_lock PAYLOAD_DATA;

static void debug_pfs_cleanup(void* arg) PAYLOAD_CODE;

static void debug_pfs_cleanup(void* arg) {
	real_sx_destroy(&s_fake_keys_lock);
}

struct real_info
{
  const size_t kernel_offset;
  const void* payload_target;
};

struct cave_info
{
  const size_t kernel_call_offset;
  const size_t kernel_ptr_offset;
  const void* payload_target;
};

struct disp_info
{
  const size_t call_offset;
  const size_t cave_offset;
};

struct real_info real_infos[] PAYLOAD_DATA =
{
  { 0x1D1700, &real_malloc },
  { 0x1D18D0, &real_free },
  { 0x286CF0, &real_memcpy },
  { 0x29cd10, &real_memcmp },
  { 0x347580, &real_printf },
  { 0x1ECB10, &real_memset },


  { 0x27AC20, &real_sx_xlock },
  { 0x27ADB0, &real_sx_xunlock },
  { 0x3369b0, &real_Sha256Hmac },
  { 0x19d880, &real_AesCbcCfb128Decrypt },
  { 0x27AB60, &real_sx_destroy },
 

  { 0x5f79b0, &real_sceSblServiceCryptAsync },
  { 0x606F40, &real_sceSblServiceMailbox },
  { 0x39a120, &real_fpu_kern_enter },
  { 0x39a220, &real_fpu_kern_leave },
  { 0X27AAF0, &real_sx_init_flags },
  { 0x4591B0, &real_eventhandler_register },

  { 0x600640, &real_sceSblPfsSetKey },
  { 0x5FF500, &real_sceSblKeymgrSmCallfunc },
  { 0x614A80, &real_sceSblAuthMgrIsLoadable2 },
  { 0x614AE0, &real_sceSblAuthMgrVerifyHeader },
  { 0x615360, &real_sceSblAuthMgrGetSelfInfo },
  { 0x6153F0, &real_sceSblAuthMgrSmStart },
  { 0x5ffe80, &real_sceSblPfsKeymgrGenEKpfsForGDGPAC },
  { 0x134B730, &M_TEMP },
  { 0x136B3E8, &mini_syscore_self_binary },
  { 0x234ED68, &sbl_driver_mapped_pages },
  { 0x2370058, &sbl_keymgr_key_rbtree },
  { 0x235C6C0, &fpu_ctx },
  { 0x1E82A0, &real_RsaesPkcs1v15Dec2048CRT },

  { 0, NULL },
};

#define ADJACENT(x) \
  x, x + 6

struct cave_info cave_infos[] PAYLOAD_DATA =
{
  // Fself hooks
  { ADJACENT(0x6116F1), &my_sceSblAuthMgrIsLoadable2 },
  { ADJACENT(0x612EA1), &my_sceSblAuthMgrVerifyHeader },
  { ADJACENT(0x617A32), &my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox },
  { ADJACENT(0x617B80), &my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox },


  // Fpkg hooks
  { ADJACENT(0x641c92), &my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif },
  { ADJACENT(0x6A4EB0), &my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new },
  { ADJACENT(0x6439b1), &my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl },
  { ADJACENT(0x6439C1), &my_sceSblPfsSetKey_pfs_sbl_init },
  { ADJACENT(0x643D21), &my_sceSblServiceCryptAsync_pfs_crypto },

  { 0, 0, NULL },
};

#undef ADJACENT

struct disp_info disp_infos[] PAYLOAD_DATA =
{
  // Fself
  //hooks     //caves
  { 0x6119B5, 0x6116F1 }, // my_sceSblAuthMgrIsLoadable2

  { 0x612149, 0x612EA1 }, // my_sceSblAuthMgrVerifyHeader
  { 0x612D81, 0x612EA1 }, // my_sceSblAuthMgrVerifyHeader

  { 0x616A6D, 0x617A32 }, // my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox

  { 0x6176C4, 0x617B80 }, // my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox

  // Fpkg 
  { 0x61fdb0, 0x641c92 },// my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif

  { 0x6202FF, 0x6A4EB0 },// my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new

  { 0x600885, 0x6439b1 },//my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl 
  { 0x600921, 0x6439b1 },//my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl

  { 0x68cfea, 0x6439C1 },//my_sceSblPfsSetKey_pfs_sbl_init
  { 0x68d078, 0x6439C1 },//my_sceSblPfsSetKey_pfs_sbl_init

  { 0x68d284, 0x643D21 },//my_sceSblServiceCryptAsync_pfs_crypto
  { 0x68d71c, 0x643D21 },//my_sceSblServiceCryptAsync_pfs_crypto
  { 0x68d974, 0x643D21 },//my_sceSblServiceCryptAsync_pfs_crypto
  { 0x68dced, 0x643D21 },//my_sceSblServiceCryptAsync_pfs_crypto
  { 0x68e11e, 0x643D21 },//my_sceSblServiceCryptAsync_pfs_crypto
  { 0x68e3b9, 0x643D21 },//my_sceSblServiceCryptAsync_pfs_crypto
  { 0x68e702, 0x643D21 },//my_sceSblServiceCryptAsync_pfs_crypto

  { 0, 0 },
};


PAYLOAD_CODE void my_entrypoint()
{
  	// initialization, etc

	real_memset(s_fake_keys, 0, sizeof(s_fake_keys));

	real_sx_init_flags(&s_fake_keys_lock, "fake_keys_lock", 0);

 	real_eventhandler_register(NULL, "shutdown_pre_sync", &debug_pfs_cleanup, NULL, 0);
}

struct
{
  uint64_t signature;
  struct real_info* real_infos;
  struct cave_info* cave_infos;
  struct disp_info* disp_infos;
  void* entrypoint;
}
payload_header PAYLOAD_HEADER =
{
  0x5041594C4F414433ull,
  real_infos,
  cave_infos,
  disp_infos,
  &my_entrypoint, 
};

// dummies -- not included in output payload binary

void PAYLOAD_DUMMY dummy()
{
  dummy();
}

int _main()
{
  return 0;
}
