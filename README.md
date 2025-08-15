This folder includes all the artifacts for the paper "TDXploit: Novel Techniques for Single-Stepping and Cache Attacks on Intel TDX".
Here we describe which folder belongs to which parts of the paper.
The only common component is the modified Linux kernel in the folder "kernel", which is used for all experiments except for the OpenSSL experiment in Section 3. 
We used a different kernel version for this experiment, which is in the folder "Section3/openssl". 
All of our code is designed to work on Ubuntu 24.04 after following the Canonical guide for setting up TDX (https://github.com/canonical/tdx).

# Section 3
## "Section3/singlestepping"
The basic implementation of TDXploit and a test victim to measure the accuracy of the attack at the beginning of Section 3.4. It consists of the host kernel module, the victim TD kernel module, and the attacker TD kernel module
## "Section3/openssl"
The code for our attack on OpenSSL ECDSA from Section 3.4.1. It contains its own kernel for this experiment, a patch file that modifies it, the traces, a user space application, the relevant kernel modules for TDXploit

# Section 4
The code for the covert channel in Section 4.2.1 is in the "Section5" folder together with the other covert channels.

## "Section4/ff_hist"
The code used to generate the histograms and evaluate clflush from Section 4.1. It contains a host kernel module and guest kernel module for the TDX measurements and a CPP file for the native measurements

## "Section4/aes"
The code used for the AES attacks described in Section 4.2.2. It contains two host kernel modules for the first round and last round T-Table attacks and the user space applications for the TD victim and the native version.

## "Section4/totp"
The code used for the OTP recovery from Section 4.2.3. It contains the host attacker kernel module, the COTP implementation, the attacker TD to facilitate TDXploit, and a decoding script to interpret the results.

# Section 5

## "Section5/systematic_evaluation"
The code for all the covert channels discussed in Section 5. "Section5/systematic_evaluation/host_receiver" contains all sender and receiver implementations for the host. "Section5/systematic_evaluation/guest_sender_pp_ff_hkid" contains the sender code for the guest for Prime+Probe, Flush+Flush, and the HKID contention channel. "Section5/systematic_evaluation/guest_sender_portsmash" contains the guest sender code for PortSmash. "Section5/systematic_evaluation/guest_receiver_ff_portsmash" contains the guest receiver code for Flush+flush and PortSmash.
