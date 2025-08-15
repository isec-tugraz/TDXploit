#define COLLECT _IO(0x41, 1)
#define END _IO(0x41, 2)

#define DEVICE_NAME "attacker"

struct __attribute__((packed)) row_t {
    unsigned long long  addr;
};

struct Args {
  struct row_t *data;
  void **num;
  unsigned long long start;
};

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

