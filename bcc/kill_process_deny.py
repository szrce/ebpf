#!/usr/bin/python
from bcc import BPF

program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>


/*
int hello_world(void *ctx) {
    bpf_trace_printk("Hello World  !\\n");
    return -1;
}*/

int block_kill(struct pt_regs *ctx) {
    bpf_trace_printk("Kill deny!\\n");
    bpf_override_return(ctx, -1); // EPERM (Permission Denied)
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("kill")
b.attach_kprobe(event=syscall, fn_name="block_kill")

b.trace_print()


#python kill_process_deny.py
