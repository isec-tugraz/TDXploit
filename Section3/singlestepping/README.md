The PoC includes the following parts:
- A modified Linux 6.8 kernel.
 The base kernel is the one provided when following this TDX guide: https://github.com/canonical/tdx
 Our modifications consist of only 3 hooks for the host kernel module, which contains the actual attack code.
 One hook right before the SEAM-call that continues the guest, one hook right after the same SEAM-call, and one hook at a later point after a vm exit occurred where interrupts are enabled.
 
- A host kernel module.
 This kernel module contains almost all of the attack code that works as described in our initial mail.
 
- An attacker kernel module.
 This kernel module is supposed to run inside of the attacker TD.
 The host continuously triggers the mitigation on this TD, and the TD  communicates the number of single steps executed through a shared page to the host.
 
- A victim kernel module.
 This kernel module is supposed to run inside of the victim TD.
 The module runs in an infinite loop in which it executes 89  instructions and then triggers a TD call to communicate to the host that a loop iteration is done.
 It should take exactly 90 single steps for one loop iteration (89 instructions + the TD call instruction).
 
To run the PoC, have the modified kernel running on the host and two single-core TDs (attacker TD and victim TD), which are pinned on the same logical core.
We also recommend isolating this core and rerouting all external interrupts to other cores (through /proc/irq/<irq  number>/smp_affinity).
The core isolation and irq rerouting reduce noise, but the attack is also very reliable without them.
Next, load the kernel modules in this order: First, the host kernel module, then the victim TD kernel module (inside the victim TD), and lastly, the attacker TD  kernel module (inside the attacker TD).
The attack should now be running.
The output can be read through "cat /sys/kernel/debug/tdxmod/data".
Counted instructions are printed through "TDX: steps counted: <number of single steps per loop iteration>".
If the number of single steps is 90, it correctly detects the 90 instructions per loop iteration in the victim.
To stop the PoC, unload the host kernel module and kill the attacker and victim TDs afterward.
