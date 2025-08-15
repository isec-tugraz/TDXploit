#include <stdbool.h>
#include <stdint.h>

// This is copy paste of the tdx step IOCTLS in <kernel
// dir>/include/uapi/linux/kvm.h

typedef struct {
  uint64_t gpa;
  int vm_pid;
} tdx_step_block_page_t;

typedef struct {
  uint64_t gpa;
  int vm_pid;
} tdx_step_unblock_page_t;

typedef struct {

  // pid of the vm that we want to attack
  int victim_vm_pid;

  uint64_t target_gpa;
  // tracking sequence to stop at the desired execution of target_gpa
  uint64_t *target_trigger_sequence;
  uint64_t target_trigger_sequence_len;

  // number of measuremnts we want to do "back to back"
  uint64_t want_attack_iterations;
  // position in `target_trigger_sequence` at which we want to launch our attack
  uint64_t tts_attack_pos;

  // set of gpas that are allowed to be executed during
  // AS_WAITING_FOR_DONE_MARKER
  uint64_t *attack_phase_allowed_gpas;
  uint64_t attack_phase_allowed_gpas_len;

  uint64_t done_marker_gpa;
  // list of gpas that should be ignored during the "track all" phase of the
  // attack
  uint64_t *ignored_gpas;
  uint64_t ignored_gpas_len;

  // TODO: add mechanism to export measurements
  // we require an uint64_t  array of this size as input to
  // TDX_STEP_TERMINATE_FR_VMCS uint64_t timings_len;

  // currently unused but probably required for export
  uint64_t gpa_shared_sigbuf;
} tdx_step_fr_vmcs_t;

typedef struct {
  bool is_done;
  uint64_t remaining_timer_interrupts;
  uint64_t want_attack_iterations;
  int attack_state;
} tdx_step_is_fr_vmcs_done_t;

typedef struct {
  // Caller allocated output parameter that must either be a
  // stumble_step_results_t or a freq_sneak_results_t depending on attack_type
  void *data;

} tdx_step_terminate_fr_vmcs_t;
// stop monitoring vmcs struct with cache attack

typedef enum {
  FREQ_SNEAK,
  STUMBLE_STEP,
  GRAZ_STEP,
} attack_type_t;

typedef struct {
  // length of "want_attack_iterations" number of measured steps for each attack
  // iteration
  uint64_t *step_counts;
  // has to have length exactly 256*4096 bytes. Will be filled with
  // want_attack_iterations many signatures. Format: For each signature, 1 byte
  // length field that states the length of the signature in bytes followed by
  // the siganture
  uint8_t *signature_data;
} graz_step_results_t;

typedef struct {
  // userspace allocated. Must have size for "want_attack_iterations" (from
  // TDX_STEP_FR_VMCS call) many entries
  uint64_t *exit_count_data;
  // userspace allocated. Must have size for "want_attack_iterations" (from
  // TDX_STEP_FR_VMCS call) many entries
  uint64_t *hit_counter_data;
} stumble_step_results_t;

typedef struct {
  // sequentially increasing id to identify this measurement
  uint64_t id;

  // If true, a tlb flush was performed during this entry
  bool tlb_flush;

  // access time for each cache set of the monitored 4KiB page
  uint64_t cache_measurements[64];

  // If true, rip and rip_delta contain valid data. Requires debug mode to be
  // enabled
  bool rip_data_valid;
  // RIP value of TD for this event
  uint64_t rip;
  // Diff to rip use by last >=1 step
  uint64_t rip_delta;

  // If true, counter_delta contains valid data. Requires gadget to increment
  // counter in shared memory and to use the appriopate paramter to pass this
  // shared memory region to the kernel
  bool counter_data_valid;
  // Dif to counter value at last >=1 step
  uint64_t counter_delta;

} freq_sneak_event_t;

typedef struct {
  // length of @freq_sneak_events_by_iteration and
  // @freq_sneak_events_by_iteration_len
  uint64_t iterations;
  // actual number valid entries in  @freq_sneak_events_by_iteration
  uint64_t *freq_sneak_events_by_iteration_len;
  // 2D array with one inner array per iteration. Each inner array must have
  // length @freq_sneak_max_event_count but may contain less valid entries, as
  // indicates by the corresponding entry in @freq_sneak_events_by_iteration_len
  freq_sneak_event_t **freq_sneak_events_by_iteration;
  // has to have length exactly 256*4096 bytes. Fill be filled with
  // want_attack_iterations many signatures. Format: For each signature, 1 byte
  // length field that states the length of the signature in bytes followed by
  // the siganture
  uint8_t *signature_data;
} freq_sneak_results_t;
