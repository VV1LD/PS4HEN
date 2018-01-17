#ifndef __FREEBSD_HELPER_H
#define __FREEBSD_HELPER_H

#define ESRCH 3
#define ENOMEM 12
#define EINVAL 22
#define ENOTSUP 45

#define	TRACEBUF	struct qm_trace trace;

#define	TAILQ_FIRST(head) ((head)->tqh_first)
#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
	TRACEBUF							\
}

#define	TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
	TRACEBUF							\
}

#define	LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;	/* next element */			\
	struct type **le_prev;	/* address of previous next element */	\
}

#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);							\
(var) = TAILQ_NEXT((var), field))

#define _countof(a) (sizeof(a)/sizeof(*(a)))


struct qm_trace {
	char * lastfile;
	int lastline;
	char * prevfile;
	int prevline;
};

struct eventhandler_entry {
	TAILQ_ENTRY(eventhandler_entry)	ee_link;
	int				ee_priority;
#define	EHE_DEAD_PRIORITY	(-1)
	void				*ee_arg;
};

typedef struct eventhandler_entry *eventhandler_tag;

void* eventhandler_register(void *list, const char *name, void *func, void *arg, int priority);



size_t countof(uint8_t array);  


static inline struct thread* curthread(void) {
	struct thread* td;

	__asm__ __volatile__ (
		"mov %0, %%gs:0"
		: "=r"(td)
	);

	return td;
}


struct lock_object
{
  const char* lo_name;
  uint32_t lo_flags;
  uint32_t lo_data;
  void* lo_witness;
};

struct sx {
	struct lock_object	lock_object;
	volatile uintptr_t	sx_lock;
};

struct mtx
{
  struct lock_object lock_object;
  volatile void* mtx_lock;
};

#endif
