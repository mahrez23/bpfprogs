#!/usr/bin/python3  
from bcc import BPF

bpf_text = r"""
BPF_PERF_OUTPUT(output); 
 
struct data_t {     
   int pid;
   int uid;
   u64 timestamp;
   char command[16];
   char message[12];
};

int function_vfs_read(void *ctx)
{
   struct data_t data = {}; 
   char message[12] = "vfs_read";
   u64 timestamp = bpf_ktime_get_ns();

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.timestamp = timestamp;

   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
 
   output.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}


int kprobe__submit_bio(void *ctx)
{
   struct data_t data = {}; 
   char message[12] = "submit_bio";
 
   u64 timestamp = bpf_ktime_get_ns();

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.timestamp = timestamp;
   
   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
 
   output.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}



"""

# hello
b = BPF(text=bpf_text)

b.attach_kprobe(event="vfs_read", fn_name="function_vfs_read")
b.attach_kprobe(event="submit_bio", fn_name="kprobe__submit_bio")

# Print output
print("Tracing VFS and block I/O operations. Press Ctrl+C to exit...")
def print_event(cpu, data, size):  
    data = b["output"].event(data)
    if "fio" in str(data.command, encoding='utf-8'):
        print(f"{data.timestamp} {data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")
 
b["output"].open_perf_buffer(print_event) 
while True:   
   b.perf_buffer_poll()
