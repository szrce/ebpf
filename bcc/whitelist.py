#!/usr/bin/python3
from bcc import BPF

program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>

#define WHITELIST_SIZE 2

// Whitelisted process
const char whitelist[WHITELIST_SIZE][16] = {
    "systemd-journal",
    "systemd-udevd"
};

int block_kill(struct pt_regs *ctx) {
    char comm[16];

    // process name
    bpf_get_current_comm(&comm, sizeof(comm));

    // whitelist check
    #pragma unroll
    for (int i = 0; i < WHITELIST_SIZE; i++) {
        if (strncmp(comm, whitelist[i], sizeof(comm)) == 0) {
            return 0; // Allow syscall
        }
    }

    // If not whitelisted, block the kill syscall
    bpf_trace_printk("Kill deny! Process: %s\\n", comm);
    bpf_override_return(ctx, -1); // EPERM (Permission Denied)
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("kill")
b.attach_kprobe(event=syscall, fn_name="block_kill")

b.trace_print()

#sudo python whitelist.py
#Linux ubuntuguest 6.11.0-18-generic #18-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb  7 22:34:25 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
#PRETTY_NAME="Ubuntu 24.10"
#NAME="Ubuntu"
#VERSION_ID="24.10"
#VERSION="24.10 (Oracular Oriole)"
#VERSION_CODENAME=oracular
#ID=ubuntu
#ID_LIKE=debian
#HOME_URL="https://www.ubuntu.com/"
#SUPPORT_URL="https://help.ubuntu.com/"
#BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
#PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
#UBUNTU_CODENAME=oracular
#LOGO=ubuntu-logo
