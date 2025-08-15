use anyhow::{Context, Result};
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::io::Write;
use std::{
    fs::File,
    io::{BufReader, BufWriter},
};

use crate::types::{freq_sneak_event_t, freq_sneak_results_t};

#[derive(Debug, Clone)]
pub struct FreqSneakResult {
    events_by_iteration_len_adjust: Vec<u64>,
    events_by_iteration: Vec<Vec<freq_sneak_event_t>>,
    #[allow(dead_code)]
    c_array: Vec<*mut freq_sneak_event_t>,
    c_struct: freq_sneak_results_t,
    raw_signatures: Vec<u8>,
}

impl FreqSneakResult {
    pub const SIGNATURE_BUFFER_BYTES: usize = 256 * 4096;
    pub const MAX_BATCH_SIZE: usize = 256 * 4096 / 70;

    pub fn new(max_entries_per_iteration: u64, iterations: u64) -> FreqSneakResult {
        let mut events_by_iteration: Vec<Vec<freq_sneak_event_t>> = vec![
                vec![freq_sneak_event_t::default(); max_entries_per_iteration as usize];
                iterations as usize
            ];

        //representation that we can pass to the c interface
        let mut c_array = vec![std::ptr::null_mut(); iterations as usize];
        //debug!("c_array vaddr: 0x{:x}", c_array.as_mut_ptr() as u64);
        for (idx, v) in events_by_iteration.iter_mut().enumerate() {
            c_array[idx] = v.as_mut_ptr();
            //debug!("c_array[{}] vaddr: 0x{:x}", idx, v.as_mut_ptr() as u64);
        }

        let mut events_by_iteration_len_adjust = vec![0_u64; iterations as usize];
        let mut raw_signatures = vec![0_u8; FreqSneakResult::SIGNATURE_BUFFER_BYTES];
        let c_struct = freq_sneak_results_t {
            iterations: iterations as u64,
            freq_sneak_events_by_iteration_len: events_by_iteration_len_adjust.as_mut_ptr(),
            freq_sneak_events_by_iteration: c_array.as_mut_ptr(),
            signature_data: raw_signatures.as_mut_ptr(),
        };
        /*debug!(
            "freq_sneak_events_by_iteration_len vaddr: 0x{:x}",
            c_struct.freq_sneak_events_by_iteration_len as u64
        );*/
        FreqSneakResult {
            events_by_iteration_len_adjust,
            events_by_iteration,
            c_array,
            c_struct,
            raw_signatures,
        }
    }

    pub fn as_freq_sneak_results_t_ref(&mut self) -> *mut freq_sneak_results_t {
        &mut self.c_struct
    }
}

pub struct ParsedFreqSneakResult {
    step_data: Vec<Vec<StepData>>,
    signatures: Vec<Vec<u8>>,
}

impl Into<ParsedFreqSneakResult> for FreqSneakResult {
    fn into(self) -> ParsedFreqSneakResult {
        let outer_len = self.events_by_iteration_len_adjust.len();
        let mut outer: Vec<Vec<StepData>> = Vec::with_capacity(outer_len);
        debug!("outer_len {}", outer_len);
        for i in 0..outer_len {
            let inner_len = self.events_by_iteration_len_adjust[i] as usize;
            let mut inner: Vec<StepData> = Vec::with_capacity(inner_len);
            debug!("inner_len {}", inner_len);
            for j in 0..inner_len {
                let c_event = self.events_by_iteration[i][j];
                inner.push(StepData::from(c_event.clone()));
            }
            outer.push(inner)
        }

        let mut offset = 0;
        let signature_count = outer.len();
        let mut signatures = Vec::new();
        for _i in 0..signature_count {
            //read uint8_t sized length specifier
            let sig_len = self.raw_signatures[offset] as usize;
            if sig_len > 69 {
                warn!(
                "Signature has {} bytes instead of expected max of 69. If this happens to often the sig buffer could overflow",
                sig_len
            );
            }

            offset += 1;
            //copy signature data
            let sig = &self.raw_signatures[offset..(offset + sig_len)].to_vec();
            signatures.push(sig.clone());
            offset += sig_len;
        }

        ParsedFreqSneakResult {
            step_data: outer,
            signatures,
        }
    }
}

pub trait ZeroStepFilter {
    fn is_zero_step(&self, s: &StepData) -> bool;
}

pub struct DefaultZeroStepFilter {
    //timing in cycles above which cache line is considered high / cache miss / cache conflict
    conflict_timing: u64,
}

impl DefaultZeroStepFilter {
    ///This filter considers something a zero step if the access times for all cache lines are below
    /// `conflict_timing``
    pub fn new(conflict_timing: u64) -> Self {
        Self { conflict_timing }
    }
}

impl ZeroStepFilter for DefaultZeroStepFilter {
    fn is_zero_step(&self, s: &StepData) -> bool {
        s.cache_measurements
            .iter()
            .filter(|v| (**v > self.conflict_timing))
            .count()
            == 0
    }
}

pub struct AllowListZeroStepFilter {
    //timing in cycles above which cache line is considered high / cache miss / cache conflict
    conflict_timing: u64,
    //only consider these cache lines (indices) when searching for high timings
    cache_set_allow_list: Vec<usize>,
}

impl AllowListZeroStepFilter {
    pub fn new(conflict_timing: u64, cache_set_allow_list: Vec<usize>) -> Self {
        Self {
            conflict_timing,
            cache_set_allow_list,
        }
    }
}

impl ZeroStepFilter for AllowListZeroStepFilter {
    fn is_zero_step(&self, s: &StepData) -> bool {
        let mut high_count = 0;
        for idx in &self.cache_set_allow_list {
            if s.cache_measurements[*idx] > self.conflict_timing {
                high_count += 1
            }
        }
        high_count == 0
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StepData {
    pub id: u64,
    pub tlb_flush: bool,
    pub rip_data_valid: bool,
    pub rip: u64,
    pub rip_delta: u64,
    pub counter_data_valid: bool,
    pub counter_delta: u64,
    pub cache_measurements: Vec<u64>,
}

impl Display for StepData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id {:04}, rip 0x{:x}, rip_delta {}",
            self.id, self.rip, self.rip_delta
        )
    }
}

/*impl StepData {
    ///Returns true if this is a zero step, i.e. all cache observations are less than the
    /// conflict_timing
    pub fn is_zero_step(
        &self,
        conflict_timing: u64,
        cache_set_allow_list: Option<&Vec<usize>>,
    ) -> bool {
        match cache_set_allow_list {
            Some(allowed_indices) => {
                let mut high_count = 0;
                for idx in allowed_indices {
                    if self.cache_measurements[*idx] > conflict_timing {
                        high_count += 1
                    }
                }
                high_count == 0
            }
            None => {
                self.cache_measurements
                    .iter()
                    .filter(|v| (**v > conflict_timing))
                    .count()
                    == 0
            }
        }
    }
}*/

impl From<freq_sneak_event_t> for StepData {
    fn from(value: freq_sneak_event_t) -> Self {
        Self {
            id: value.id,
            tlb_flush: value.tlb_flush,
            rip_data_valid: value.rip_data_valid,
            rip: value.rip,
            rip_delta: value.rip_delta,
            counter_data_valid: value.counter_data_valid,
            counter_delta: value.counter_delta,
            cache_measurements: value.cache_measurements.into(),
        }
    }
}

/// serialize into two csv files, one with data flattened (i.e. all iterations in one csv) and one metadata files with the lenghts of the inner arrays. The latter allows to reconstruction the individual iterations later on if required
/// # Arguments
/// - `data`: Measurements grouped by attack iteration
/// - `file_prefix`: common prefix for output files, no file extension!
pub fn store_as_csv(freq_sneak_data: ParsedFreqSneakResult, file_prefix: String) -> Result<()> {
    let data_path = format!("{}_data.csv", file_prefix.clone());
    let metadata_path = format!("{}_metadata.csv", file_prefix.clone());
    let signature_path = format!("{}_signatures.csv", file_prefix.clone());

    //Store length of each step data measurement as metadata, to be able to separate the data again later on
    let metadata: Vec<usize> = freq_sneak_data.step_data.iter().map(|v| v.len()).collect();
    let mut step_metadata_writer =
        csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(BufWriter::new(
                File::create(metadata_path.clone())
                    .context(format!("Failed to create metadata file{}", metadata_path))?,
            ));
    step_metadata_writer
        .serialize(metadata)
        .context("failed to serialize metadata")?;

    debug!("data: outer len  {}", freq_sneak_data.step_data.len());
    //Store actual step data
    let mut step_data_writer =
        csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(BufWriter::new(
                File::create(data_path.clone())
                    .context(format!("Failed to create data file{}", data_path))?,
            ));

    for outer in freq_sneak_data.step_data {
        for inner in outer {
            step_data_writer
                .serialize(inner)
                .context("failed to serialize data entry")?;
        }
    }

    //Store signatures
    let mut signature_writer = BufWriter::new(
        File::create(signature_path.clone())
            .context(format!("Failed to create signature file{}", signature_path))?,
    );
    for sig in freq_sneak_data.signatures {
        write!(signature_writer, "0x{}\n", hex::encode(sig))
            .context("failed to write signature")?;
    }

    Ok(())
}

pub fn load_from_csv(
    data_file_path: String,
    metadata_file_path: String,
) -> Result<Vec<Vec<StepData>>> {
    //read metadata
    let mut metadata_reader =
        csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(BufReader::new(
                File::open(metadata_file_path.clone()).context(format!(
                    "failed to open metadata file {}",
                    metadata_file_path.clone()
                ))?,
            ));

    let metadata: Vec<u64> = metadata_reader
        .deserialize()
        .next()
        .context(format!(
            "metadata file is {} empty",
            metadata_file_path.clone()
        ))?
        .context("failed to deserialize metadata")?;

    //read data
    let mut data_reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(BufReader::new(File::open(data_file_path.clone()).context(
            format!("failed to open data file {}", data_file_path.clone()),
        )?));

    let mut data: Vec<StepData> = Vec::new();
    for entry in data_reader.deserialize() {
        data.push(entry.context("failed to deserialize data entry")?);
    }

    //split data according to metadata
    let mut data_by_iteration: Vec<Vec<StepData>> = Vec::new();
    let mut metadata_iter = metadata.iter();
    let mut want_in_current_iteration = metadata_iter.next().context("metadata empty")?;
    let mut current_iteration_data: Vec<StepData> = Vec::new();
    for (idx, v) in data.into_iter().enumerate() {
        if current_iteration_data.len() < *want_in_current_iteration as usize {
            current_iteration_data.push(v);
        } else {
            data_by_iteration.push(current_iteration_data);
            current_iteration_data = Vec::new();
            current_iteration_data.push(v);
            want_in_current_iteration = metadata_iter
                .next()
                .context(format!("missing metadata for entries after idx {}", idx))?;
        }
    }

    Ok(data_by_iteration)
}
