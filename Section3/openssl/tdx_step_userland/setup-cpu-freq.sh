#!/bin/bash
#This requires that the "acpi-cpufreq" scaling driver is used. To achieve this, you need to set "Socket Configuration->Advanced Power Management Configuration->Hardware PM State Control->Hardware P-States" to disabled in the BIOS. Otherwise the "intel_pstate" scaling driver is loaded and the HW mostly manages the P-States on its own
set -e
#available frequencies 2001000 2000000 1900000 1800000 1700000 1600000 1500000 1400000 1300000 1200000 1100000 1000000 900000 800000
#for high conflict timing tdvps/tdvpx pages use 1100000
#for counting attack against `--tdvps-indices 0  --offset-in-target-vaddr 1088` use 1200000
VICTIM_CORE=10
VICTIM_FREQ=800000
echo "Fixating freq of victim core ${VICTIM_CORE} at ${VICTIM_FREQ}"
echo "userspace" | sudo tee /sys/devices/system/cpu/cpu${VICTIM_CORE}/cpufreq/scaling_governor  > /dev/null
echo $VICTIM_FREQ    | sudo tee /sys/devices/system/cpu/cpu${VICTIM_CORE}/cpufreq/scaling_setspeed  >/dev/null

ATTACKER_FREQ=2800000
for i in 11 27
do 
	echo "Fixating freq of attacker core ${i} at ${ATTACKER_FREQ}"
	echo "userspace" | sudo tee /sys/devices/system/cpu/cpu${i}/cpufreq/scaling_governor  > /dev/null
	echo $ATTACKER_FREQ    | sudo tee /sys/devices/system/cpu/cpu${i}/cpufreq/scaling_setspeed > /dev/null
done
