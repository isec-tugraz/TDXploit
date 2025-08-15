use std::ops::AddAssign;

use anyhow::{bail, Context, Result};
use clap::Parser;
use file_helpers::prefix_to_filename_tuple;
use indicatif::HumanCount;
use serde::Serialize;
use std::default::Default;
use tdx_step_userland::freq_sneak::{self, DefaultZeroStepFilter, StepData, ZeroStepFilter};

use crate::file_helpers::get_file_list;

mod file_helpers;

#[derive(clap::ValueEnum, Clone, Debug, Serialize, Copy)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    //Verify that each iteration has an expected number of events
    Check,
    //Format data for humans
    DumpHuman,
    //Format data for attack classifier
    DumpClassifier,
}

#[derive(Parser, Debug)]
struct CliArgs {
    #[arg(long, short, default_value = "check")]
    mode: Mode,

    ///Specify a single input file
    #[arg(long)]
    in_prefix: Option<String>,

    //Analyze all files in this folder. Assumes naming attack-results-{}_{}_metadata.csv and  attack-results-{}_{}_data.csv
    #[arg(long)]
    in_folder: Option<String>,

    ///Threshhold above which cache timings are considered a KeyID conflict
    #[arg(long, default_value = "499")]
    conflict_timing: u64,

    ///Expected number of steps PER iteration
    #[arg(long)]
    want_steps: Option<usize>,
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    //generate list of input files that should get processed
    let input_files;
    if let Some(v) = args.in_prefix.clone() {
        input_files = vec![prefix_to_filename_tuple(&v)];
    } else if let Some(v) = args.in_folder.clone() {
        println!("Reading files from folder {}", v.clone());
        input_files = get_file_list(v.clone())
            .context(format!("error listing files in folder {}", v.clone()))?;
    } else {
        bail!("Either in-prefix or in-folder arg is required");
    }

    let zero_step_filter = DefaultZeroStepFilter::new(args.conflict_timing);

    match args.mode.clone() {
        Mode::Check => {
            let mut combined_results = CheckResult::default();
            for (data_path, metadata_path) in input_files {
                eprintln!("Checking {}", data_path);
                let data_by_iteration = freq_sneak::load_from_csv(data_path, metadata_path)
                    .context("failed to parse")?;
                let r = check_mode(&args, &data_by_iteration, &zero_step_filter)
                    .context("check_mode failed")?;

                combined_results += r;
            }
            println!(
                "Total stats: stepping events {}, zero steps: {}, \"cleaned\" zero steps {}, single steps {}",
                HumanCount(combined_results.total_stepping_events as u64),
                HumanCount(combined_results.zero_steps as u64),
                HumanCount(combined_results.cleaned_zero_steps as u64),
                HumanCount((combined_results.total_stepping_events - combined_results.zero_steps) as u64),
            );
        }
        Mode::DumpHuman => {
            for (data_path, metadata_path) in input_files {
                let data_by_iteration = freq_sneak::load_from_csv(data_path, metadata_path)
                    .context("failed to parse")?;
                dump_human_mode(&data_by_iteration, &zero_step_filter);
            }
        }
        Mode::DumpClassifier => {
            for (data_path, metadata_path) in input_files {
                let data_by_iteration = freq_sneak::load_from_csv(data_path.clone(), metadata_path)
                    .context("failed to parse")?;
                dump_classifier_mode(&args, &data_by_iteration, &zero_step_filter, &data_path);
            }
        }
    };

    Ok(())
}

fn dump_classifier_mode(
    _args: &CliArgs,
    data_by_iteration: &Vec<Vec<StepData>>,
    zero_step_filter: &impl ZeroStepFilter,
    data_path: &str,
) {
    for (iteration_idx, iteration) in data_by_iteration.iter().enumerate() {
        for event in iteration.iter().skip(1) {
            let is_zero_step: bool = zero_step_filter.is_zero_step(event);
            if event.rip_data_valid && ((event.rip_delta == 0) != is_zero_step) {
                println!(
                    "{}, iteration_idx {}, event {}, classification error, rip_delta {} and is_zero_step? {}",
                    data_path, iteration_idx, event.id, event.rip_delta, is_zero_step
                );
                return;
            }
        }
        let got_single_steps = iteration
            .iter()
            .filter(|v| !zero_step_filter.is_zero_step(v))
            .count();
        println!(
            "{}, iteration_idx {}, steps {}",
            data_path, iteration_idx, got_single_steps
        );
    }
}

fn dump_human_mode(data_by_iteration: &Vec<Vec<StepData>>, zero_step_filter: &impl ZeroStepFilter) {
    for (iteration_idx, iteration) in data_by_iteration.iter().enumerate() {
        print!("\n\nIteration at idx {}\n\n", iteration_idx);
        for v in iteration {
            let is_zero_step = zero_step_filter.is_zero_step(v);
            if v.rip_data_valid {
                println!(
                    "id {:05}, zero_step? {}, rip 0x{:x}, rip_delta {}",
                    v.id, is_zero_step, v.rip, v.rip_delta,
                )
            } else {
                println!("id {:05}, zero_step? {}", v.id, is_zero_step,)
            }
        }
    }
}

#[derive(Default)]
struct CheckResult {
    zero_steps: usize,
    cleaned_zero_steps: usize,
    total_stepping_events: usize,
}

impl AddAssign for CheckResult {
    fn add_assign(&mut self, rhs: Self) {
        self.zero_steps += rhs.zero_steps;
        self.cleaned_zero_steps += rhs.cleaned_zero_steps;
        self.total_stepping_events += rhs.total_stepping_events
    }
}

fn check_mode(
    args: &CliArgs,
    data_by_iteration: &Vec<Vec<StepData>>,
    zero_step_filter: &impl ZeroStepFilter,
) -> Result<CheckResult> {
    let want_steps = args
        .want_steps
        .context("check mode requires want-steps parameter")?;

    if !check_step_count_per_iteration(&data_by_iteration, want_steps, zero_step_filter) {
        bail!("Not all iterations have the expected amount of single step events");
    }
    println!("\t All iterations have {} steps ✅", want_steps);

    let total_step_count: usize = data_by_iteration
        .iter()
        .map(|iteration| iteration.len())
        .sum();
    let total_zero_step_count: usize = data_by_iteration
        .iter()
        .map(|iteration| {
            iteration
                .iter()
                .filter(|v| zero_step_filter.is_zero_step(v))
                .count()
        })
        .sum();
    let cleaned_zero_step_count: usize = data_by_iteration
        .iter()
        .map(|iteration| {
            iteration
                .iter()
                //see comment below, first instruction is always a zero step, thus we ignore it in our analysis
                .skip(1)
                .filter(|v| zero_step_filter.is_zero_step(v))
                .count()
        })
        .sum();

    let cleaned_zero_step_percent = cleaned_zero_step_count as f64
        / (total_step_count - cleaned_zero_step_count) as f64
        * 100.0;
    println!(
        "\t{} step events, {} zero steps, {} \"cleaned\" zero steps ({:.02}%)",
        HumanCount(total_step_count as u64),
        HumanCount(total_zero_step_count as u64),
        HumanCount(cleaned_zero_step_count as u64),
        cleaned_zero_step_percent,
    );
    Ok(CheckResult {
        zero_steps: total_zero_step_count,
        cleaned_zero_steps: cleaned_zero_step_count,
        total_stepping_events: total_step_count,
    })
}

/// Checks that each iteration has `want_steps` many single stepping events when using
/// `conflict_timing` for the cache-based classification
fn check_step_count_per_iteration(
    data_by_iteration: &Vec<Vec<StepData>>,
    want_steps: usize,
    zero_step_filter: &impl ZeroStepFilter,
) -> bool {
    let mut check_status = true;
    for (iteration_idx, iteration) in data_by_iteration.iter().enumerate() {
        //used to control some print logic
        let mut iteration_status = true;

        //Check 1: number of single steps matches the expected amount of exeucted instructions
        let got_single_steps = iteration
            .iter()
            .filter(|v| !zero_step_filter.is_zero_step(v))
            .count();
        if got_single_steps != want_steps {
            println!(
                "Iteration idx {} has {} steps but want {}",
                iteration_idx, got_single_steps, want_steps
            );
            if iteration.len() < 50 {
                for v in iteration {
                    println!("\t{}. Raw Cache Data: {:?}", v, v.cache_measurements);
                }
            }
            check_status = false;
            iteration_status = false;
        }

        //Check 2: Only for debug traces with rip : check that rip matches expected value
        {
            if iteration[0].rip_data_valid {
                let mut expected_rips = Vec::new();
                let start_marker_rip = 0x5637f4775000;
                let stop_marker_rip = 0x5637f4775010;
                let base_rip_seq = vec![
                    0x5637f4775007,
                    0x5637f477500a,
                    0x5637f477500b,
                    0x5637f477500c,
                    0x5637f477500d,
                    0x5637f477500e,
                ];
                let reps = 50;
                expected_rips.push(start_marker_rip);
                for _i in 0..reps {
                    expected_rips.append(&mut base_rip_seq.clone());
                }
                expected_rips.push(stop_marker_rip);
                if let Some(misclassified_event) = find_missclassified_events_with_debug(
                    iteration,
                    &expected_rips,
                    zero_step_filter,
                ) {
                    //only print iteration if the previous checks have passed. Otherwise they have
                    //already printed the iteration
                    if iteration_status {
                        println!("Iteration idx {} has expected amount of steps but mismatching rip sequence",iteration_idx);
                        iteration_status = false;
                    }
                    match misclassified_event.violation_type {
                        RipViolationType::UndetectedZeroStep(expected_rip) =>  println!(
                        "\tUndetected zero step at id {}. Have rip 0x{:x} but should have rip 0x{:x}",
                        misclassified_event.event.id, misclassified_event.event.rip, expected_rip
                    ),
                        RipViolationType::UndetectedSingleStep =>  println!(
                        "\tUndetected single step at id {} with rip 0x{:x}",
                        misclassified_event.event.id, misclassified_event.event.rip,
                    ),
                    }

                    println!("\tAborting here");
                }
            } else {
                println!("No rip data, skipping vaddr check");
            }
        }
    }
    check_status
}

enum RipViolationType {
    ///Event is a zero step but not detected as such. Inner data is exepected rip value
    UndetectedZeroStep(u64),
    //Event is a single step but detected as a zero step
    UndetectedSingleStep,
}
struct RipCheckViolation {
    event: StepData,
    violation_type: RipViolationType,
}

/// Expects StepData to have RIP information and checks that events have the expected rip value
/// Aborts at the first error
fn find_missclassified_events_with_debug(
    iteration: &Vec<StepData>,
    expected_rips: &Vec<u64>,
    zero_step_filter: &impl ZeroStepFilter,
) -> Option<RipCheckViolation> {
    let mut expected_rip_iter = expected_rips.iter();
    let mut prev_rip = None;
    for event in iteration {
        if zero_step_filter.is_zero_step(event) {
            if prev_rip.is_some_and(|prev: u64| event.rip != prev) {
                return Some(RipCheckViolation {
                    event: event.clone(),
                    violation_type: RipViolationType::UndetectedSingleStep,
                });
            }
            //go to next event WITHOUT increasing the rip_idx
            continue;
        }
        let expected_rip = expected_rip_iter.next().expect("expected rips to short");
        if event.rip != *expected_rip {
            return Some(RipCheckViolation {
                event: event.clone(),
                violation_type: RipViolationType::UndetectedZeroStep(*expected_rip),
            });
        }
        prev_rip = Some(*expected_rip);
    }
    return None;
}
