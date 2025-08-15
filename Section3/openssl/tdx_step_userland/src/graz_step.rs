use std::{fs::File, io::BufWriter};

use anyhow::{Context, Result};
use log::{debug, warn};
use std::io::Write;

use crate::types::graz_step_results_t;

#[derive(Debug, Clone)]
pub struct GrazStepResult {
    ///Number of recorded steps for each attack run
    step_counts: Vec<u64>,
    raw_signatures: Vec<u8>,
    c_struct: graz_step_results_t,
}

impl GrazStepResult {
    pub const SIGNATURE_BUFFER_BYTES: usize = 256 * 4096;
    pub const MAX_BATCH_SIZE: usize = 256 * 4096 / 70;

    pub fn new(attack_iterations: u64) -> GrazStepResult {
        let mut step_counts = vec![0; attack_iterations as usize];
        let mut raw_signatures = vec![0_u8; GrazStepResult::SIGNATURE_BUFFER_BYTES];
        let c_struct = graz_step_results_t {
            step_counts: step_counts.as_mut_ptr(),
            signature_data: raw_signatures.as_mut_ptr(),
        };
        GrazStepResult {
            step_counts,
            raw_signatures,
            c_struct,
        }
    }

    pub fn as_graz_step_results_t(&mut self) -> *mut graz_step_results_t {
        &mut self.c_struct
    }
}

impl Into<ParsedGrazStepResult> for GrazStepResult {
    fn into(self) -> ParsedGrazStepResult {
        let mut offset = 0;
        let signature_count = self.step_counts.len();
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

        ParsedGrazStepResult {
            step_counts: self.step_counts,
            signatures,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedGrazStepResult {
    ///Number of recorded steps for each attack run
    step_counts: Vec<u64>,
    signatures: Vec<Vec<u8>>,
}

impl ParsedGrazStepResult {
    pub fn store_as_csv(&self, file_prefix: String) -> Result<()> {
        let data_path = format!("{}_data.csv", file_prefix.clone());
        let signature_path = format!("{}_signatures.csv", file_prefix.clone());

        let mut step_data_writer =
            csv::WriterBuilder::new()
                .has_headers(false)
                .from_writer(BufWriter::new(
                    File::create(data_path.clone())
                        .context(format!("Failed to create data file{}", data_path))?,
                ));

        debug!("serializing self.step_counts = {:?}", self.step_counts);
        step_data_writer
            .serialize(&self.step_counts)
            .context("failed to serialize step counts")?;

        //Store signatures
        let mut signature_writer = BufWriter::new(
            File::create(signature_path.clone())
                .context(format!("Failed to create signature file{}", signature_path))?,
        );
        for sig in &self.signatures {
            write!(signature_writer, "0x{}\n", hex::encode(sig))
                .context("failed to write signature")?;
        }

        Ok(())
    }
}
