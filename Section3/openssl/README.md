# TDXploit Artifacts

The attack infrastructure is heavily based on the [tdxdown artifacts](https://github.com/UzL-ITS/tdxdown). See their readme for background information on the general attack setup

## Kernel
The kernel patch is against the version 6.8.4_6.8.4-17 (same as disclosure to intel)

## Attack victim
Our attack target and the leakage analysis are the same from the tdxdown paper artifact.
- Target: `tdxdown-paper-artifacts/single-stepping/our-attack-tools/openssl-attack-victim`
- Analysis: `cryptanalysis` (follow route for Openssl)
See the respective parts in their readme for setting them up.


## Attack control app

The code for starting/controlling the attack is in the `tdx_step_userland` folder
Build with `cargo build --release`. 

Attack command

```bash
sudo -E RUST_LOG=debug ./target/release/apic_attack --vm-pid $(cat /tmp/victim-td-pid.pid) --attack-type graz-step --cpu-vm <cpu vm is pinned to > --total-number-of-measurements 10000 --batch-size 10000 --abstract-sequence-mapping <line from "Mapping for unique paddrs in ts"> --stop-gpa <paddr from "Code Location stopTrigger" line > --allowed-during-attack <value from "Allowed during attack phase" line > --ts-target-idx 442 --target-code-gpa <value from "Allowed during attack phase"> --manual-end-of-seq-gpa <value from "gpa end_of_seq_marker"> --gpa-signature-buffer <GPA_SHARED from dmesg output>
```  

In addition to the setup described in the tdxdown paper we will also need to start our helper td and load a few additional kernel modules


The `traces` folder contains the traces that we gathered for the evaluation in the paper.
We used traces with 42 to 44 reported steps. We were unable to verify why there is a difference to the number reported in tdxdown
