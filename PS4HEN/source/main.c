#include <assert.h>

#include "ps4.h"

const uint8_t payload_data_const[] =
{
#include "payload_data.inc"
};

uint64_t __readmsr(unsigned long __register)
{
  unsigned long __edx;
  unsigned long __eax;
  __asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
  return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline)) uint64_t readCr0(void)
{
  uint64_t cr0;
  __asm__ volatile ("movq %0, %%cr0" : "=r" (cr0) : : "memory");
  return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0)
{
  __asm__ volatile("movq %%cr0, %0" : : "r" (cr0) : "memory");
}

struct payload_info
{
  uint8_t* buffer;
  size_t size;
};

struct syscall_install_payload_args
{
  void* syscall_handler;
  struct payload_info* payload_info;
};

struct real_info
{
  const size_t kernel_offset;
  const size_t payload_offset;
};

struct cave_info
{
  const size_t kernel_call_offset;
  const size_t kernel_ptr_offset;
  const size_t payload_offset;
};

struct disp_info
{
  const size_t call_offset;
  const size_t cave_offset;
};

struct payload_header
{
  uint64_t signature;
  size_t real_info_offset;
  size_t cave_info_offset;
  size_t disp_info_offset;
  size_t entrypoint_offset;
};

int syscall_install_payload(void* td, struct syscall_install_payload_args* args)
{
  uint64_t cr0;
  typedef uint64_t vm_offset_t;
  typedef uint64_t vm_size_t;
  typedef void* vm_map_t;

  void* (*kernel_memcpy)(void* dst, const void* src, size_t len);
  void (*kernel_printf)(const char* fmt, ...);
  vm_offset_t (*kmem_alloc)(vm_map_t map, vm_size_t size);

  uint8_t* kernel_base = (uint8_t*)(__readmsr(0xC0000082) - 0x3095d0);

  *(void**)(&kernel_printf) = &kernel_base[0x17F30];
  *(void**)(&kernel_memcpy) = &kernel_base[0x14A6B0];
  *(void**)(&kmem_alloc) = &kernel_base[0x16ECD0];
  vm_map_t kernel_map = *(void**)&kernel_base[0x1B31218];

  kernel_printf("\n\n\n\npayload_installer: starting\n");
  kernel_printf("payload_installer: kernel base=%lx\n", kernel_base);

  if (!args->payload_info)
  {
    kernel_printf("payload_installer: bad payload info\n");
    return -1;
  }

  uint8_t* payload_data = args->payload_info->buffer;
  size_t payload_size = args->payload_info->size;
  struct payload_header* payload_header = (struct payload_header*)payload_data;

  if (!payload_data ||
      payload_size < sizeof(payload_header) ||
      payload_header->signature != 0x5041594C4F414433ull)
  {
    kernel_printf("payload_installer: bad payload data\n");
    return -2;
  }

  int desired_size = (payload_size + 0x3FFFull) & ~0x3FFFull; // align size

  // TODO(idc): clone kmem_alloc instead of patching directly
  cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);
  kernel_base[0x16ed8c] = 7; 
  kernel_base[0x16eda2] = 7; 
  writeCr0(cr0);

  kernel_printf("payload_installer: kmem_alloc\n");
  uint8_t* payload_buffer = (uint8_t*)kmem_alloc(kernel_map, desired_size);
  if (!payload_buffer)
  {
    kernel_printf("payload_installer: kmem_alloc failed\n");
    return -3;
  }

  // TODO(idc): clone kmem_alloc instead of patching directly
  cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);
  kernel_base[0x16ed8c] = 3; 
  kernel_base[0x16eda2] = 3; 
  writeCr0(cr0);

  kernel_printf("payload_installer: installing...\n");
  kernel_printf("payload_installer: target=%lx\n", payload_buffer);
  kernel_printf("payload_installer: payload=%lx,%lu\n",
    payload_data, payload_size);

  kernel_printf("payload_installer: memcpy\n");
  kernel_memcpy((void*)payload_buffer, payload_data, payload_size);

  kernel_printf("payload_installer: patching payload pointers\n");
  if (payload_header->real_info_offset != 0 &&
    payload_header->real_info_offset + sizeof(struct real_info) <= payload_size)
  {
    struct real_info* real_info =
      (struct real_info*)(&payload_data[payload_header->real_info_offset]);
    for (
      ; real_info->payload_offset != 0 && real_info->kernel_offset != 0
      ; ++real_info)
    {
      uint64_t* payload_target =
        (uint64_t*)(&payload_buffer[real_info->payload_offset]);
      void* kernel_target = &kernel_base[real_info->kernel_offset];
      *payload_target = (uint64_t)kernel_target;
      kernel_printf("  %x(%lx) = %x(%lx)\n",
        real_info->payload_offset, payload_target,
        real_info->kernel_offset, kernel_target);
    }
  }

  kernel_printf("payload_installer: patching caves\n");
  if (payload_header->cave_info_offset != 0 &&
    payload_header->cave_info_offset + sizeof(struct cave_info) <= payload_size)
  {
    struct cave_info* cave_info =
      (struct cave_info*)(&payload_data[payload_header->cave_info_offset]);
    for (
      ; cave_info->kernel_call_offset != 0 &&
        cave_info->kernel_ptr_offset != 0 &&
        cave_info->payload_offset != 0
      ; ++cave_info)
    {
      uint8_t* kernel_call_target = &kernel_base[cave_info->kernel_call_offset];
      uint8_t* kernel_ptr_target = &kernel_base[cave_info->kernel_ptr_offset];
      void* payload_target = &payload_buffer[cave_info->payload_offset];
      int32_t new_disp = (int32_t)(kernel_ptr_target - &kernel_call_target[6]);

      if (&kernel_call_target[6] == kernel_ptr_target)
      {
        kernel_printf("  %lx(%lx) = %d\n",
          cave_info->kernel_call_offset, kernel_call_target,
          new_disp);

        if ((uint64_t)(kernel_ptr_target - &kernel_call_target[6]) != 0)
        {
          kernel_printf("  error: new_disp != 0!\n");
        }
      }
      else
      {
        kernel_printf("  %lx(%lx) -> %lx(%lx) = %d\n",
          cave_info->kernel_call_offset, kernel_call_target,
          cave_info->kernel_ptr_offset, kernel_ptr_target,
          new_disp);

        if ((uint64_t)(kernel_ptr_target - &kernel_call_target[6]) > UINT32_MAX)
        {
          kernel_printf("  error: new_disp > UINT32_MAX!\n");
        }
      }
      kernel_printf("    %lx(%lx)\n",
        cave_info->payload_offset, payload_target);

#pragma pack(push,1)
      struct
      {
        uint8_t op[2];
        int32_t disp;
      }
      jmp;
#pragma pack(pop)
      jmp.op[0] = 0xFF;
      jmp.op[1] = 0x25;
      jmp.disp = new_disp;
      cr0 = readCr0();
      writeCr0(cr0 & ~X86_CR0_WP);
      kernel_memcpy(kernel_call_target, &jmp, sizeof(jmp));
      kernel_memcpy(kernel_ptr_target, &payload_target, sizeof(void*));
      writeCr0(cr0);
    }
  }

  kernel_printf("payload_installer: patching calls\n");
  if (payload_header->disp_info_offset != 0 &&
    payload_header->disp_info_offset + sizeof(struct disp_info) <= payload_size)
  {
    struct disp_info* disp_info =
      (struct disp_info*)(&payload_data[payload_header->disp_info_offset]);
    for (
      ; disp_info->call_offset != 0 && disp_info->cave_offset != 0
      ; ++disp_info)
    {
      uint8_t* cave_target = &kernel_base[disp_info->cave_offset];
      uint8_t* call_target = &kernel_base[disp_info->call_offset];

      int32_t new_disp = (int32_t)(cave_target - &call_target[5]);

      kernel_printf("  %lx(%lx)\n",
        disp_info->call_offset + 1, &call_target[1]);
      kernel_printf("    %lx(%lx) -> %lx(%lx) = %d\n",
        disp_info->call_offset + 5, &call_target[5],
        disp_info->cave_offset, cave_target,
        new_disp);

      cr0 = readCr0();
      writeCr0(cr0 & ~X86_CR0_WP);
      *((int32_t*)&call_target[1]) = new_disp;
      writeCr0(cr0);
    }
  }

  if (payload_header->entrypoint_offset != 0 &&
    payload_header->entrypoint_offset < payload_size)
  {
    kernel_printf("payload_installer: entrypoint\n");
    void (*payload_entrypoint)();
    *((void**)&payload_entrypoint) =
      (void*)(&payload_buffer[payload_header->entrypoint_offset]);
    payload_entrypoint();
  }

  kernel_printf("payload_installer: done\n");
  return 0;
}
struct auditinfo_addr {
    /*
    4    ai_auid;
    8    ai_mask;
    24    ai_termid;
    4    ai_asid;
    8    ai_flags;r
    */
    char useless[184];
};


struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
 	uint32_t useless2;
    	uint32_t useless3;
    	uint32_t cr_rgid;    // real group id
    	uint32_t useless4;
    	void *useless5;
    	void *useless6;
    	void *cr_prison;     // jail(2)
    	void *useless7;
    	uint32_t useless8;
    	void *useless9[2];
    	void *useless10;
    	struct auditinfo_addr useless11;
    	uint32_t *cr_groups; // groups
    	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
    	void *fd_rdir;
    	void *fd_jdir;
};

struct proc {
    	char useless[64];
    	struct ucred *p_ucred;
    	struct filedesc *p_fd;
};



struct thread {
    	void *useless;
    	struct proc *td_proc;
};

struct kpayload_args{
	uint64_t user_arg;
};

struct kdump_args{
    	uint64_t argArrayPtr;
};


int kpayload(struct thread *td){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x3095D0];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[0x10399B0];
	void** got_rootvnode = (void**)&kernel_ptr[0x21AFA30];

	// resolve kernel functions

	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x14A7B0);
	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x17F30);
	void* (*kmalloc)(size_t size) = (void *)(kernel_base + 0x3F7750);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3800000000000013; 
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// enable uart :)
	*(char *)(kernel_base + 0x1997BC8) = 0; 

	// specters debug settings patchs

	*(char *)(kernel_base + 0x1B6D086) |= 0x14;
	*(char *)(kernel_base + 0x1B6D0A9) |= 0x3;
	*(char *)(kernel_base + 0x1B6D0AA) |= 0x1;
	*(char *)(kernel_base + 0x1B6D0C8) |= 0x1;

	// debug menu full patches
	*(uint32_t *)(kernel_base + 0x4D70F7) = 0;
	*(uint32_t *)(kernel_base + 0x4D7F81) = 0;

	 //kern_sdk_vesion spoofer from lightning mods :)
	*(uint32_t *)(kernel_base + 0x144B600) = 0x5050001;

	// Disable ptrace checks
	*(uint32_t*)&kernel_ptr[0x17D2EE] = 0x90909090;
	*(uint16_t*)&kernel_ptr[0x17D2F2] = 0x9090;

	// verbose panic patch
	*(uint32_t*)&kernel_ptr[0x3DBDC7] = 0x90909090;
	*(char*)&kernel_ptr[0x3DBDCB] = 0x90;

	// flatz rsa check patch ;)
    	*(uint32_t *)(kernel_base + 0x69F4E0) = 0x90c3c031;

	// flatz enable debug rifs ;)

    	*(uint64_t *)(kernel_base + 0x62D30D) = 0x3D38EB00000001B8;	 

	// restore write protection

	writeCr0(cr0);

	// Say hello and put the kernel base just for reference

	printfkernel("\n\n\nHELLO FROM YOUR KERN DUDE =)\n\n\n");
	printfkernel("kernel base is:0x%016llx\n", kernel_base);

	return 0;
}


int _main(struct thread *td)
{
  uint8_t* payload_data = (uint8_t*)(&payload_data_const[0]);
  size_t payload_size = sizeof(payload_data_const);

//hold on.. we need to do some setup first :)

  // do some inits
  initKernel();
  initLibc();
  initPthread();

  // patch the kernel
  syscall(11,kpayload,td);

  // patch the shell
  do_patch();

// ok now lets call the installer

  struct payload_info payload_info;
  payload_info.buffer = payload_data;
  payload_info.size = payload_size;
  errno = 0;
  int result = kexec(&syscall_install_payload, &payload_info);
  return !result ? 0 : errno;
}
