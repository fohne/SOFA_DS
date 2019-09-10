#!/usr/bin/python
from bcc import BPF

# define BPF program
prog = """
#include <linux/sched.h>
#include <linux/skbuff.h>



struct data_t {
    u64 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    int net_layer;
    unsigned int len, data_len;
    u8 type;
};
BPF_PERF_OUTPUT(events);

int cb = 0;

static void pid_comm_ts(struct data_t* data) {
    data->pid = bpf_get_current_pid_tgid();
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&(data->comm), sizeof(data->comm));
}

static void topdown_trace(struct data_t* data,struct sk_buff *skb) {

}


int rx_action(struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = 1;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int netif_receive(struct pt_regs *ctx) {
    struct data_t data = {};
    struct sk_buff *skb;
    skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    data.len = skb->len;
    data.data_len = skb->data_len;
    data.type = (*skb).pkt_type;

    pid_comm_ts(&data);
    data.net_layer = 2;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int ip_r(struct pt_regs *ctx) {
    struct data_t data = {};
    struct sk_buff *skb;
    skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    data.len = skb->len;
    data.data_len = skb->data_len;
    data.type = (*skb).pkt_type;
    
    pid_comm_ts(&data);
    data.net_layer = 3;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int udp_r(struct pt_regs *ctx) {
    struct data_t data = {};
    struct sk_buff *skb;
    skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    data.len = skb->len;
    data.data_len = skb->data_len;
    data.type = (*skb).pkt_type;

    pid_comm_ts(&data);
    data.net_layer = 4;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int return_rx_action(struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = -1;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int return_netif_receive(struct pt_regs *ctx) {
    struct data_t data = {};
    struct sk_buff *skb;
    skb = (struct sk_buff *) PT_REGS_PARM1(ctx);

    pid_comm_ts(&data);
    data.net_layer = -2;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int return_ip_r(struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = -3;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int return_udp_r(struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = -4;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int return_data_ready(struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = -5;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int data_ready(struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = 5;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int recv_from(struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = 6;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

"""

# load BPF program
b = BPF(text=prog)


b.attach_kprobe(event="net_rx_action", fn_name="rx_action")
b.attach_kprobe(event="__netif_receive_skb_one_core", fn_name="netif_receive")
b.attach_kprobe(event="ip_rcv", fn_name="ip_r")
b.attach_kprobe(event="udp_rcv", fn_name="udp_r")
b.attach_kprobe(event="sock_def_readable", fn_name="data_ready")
b.attach_uprobe(name="c", sym="recvfrom", fn_name="recv_from")

b.attach_kretprobe(event="net_rx_action", fn_name="return_rx_action")
b.attach_kretprobe(event="__netif_receive_skb_one_core", fn_name="return_netif_receive")
b.attach_kretprobe(event="ip_rcv", fn_name="return_ip_r")
b.attach_kretprobe(event="udp_rcv", fn_name="return_udp_r")
b.attach_kprobe(event="sock_def_readable", fn_name="return_data_ready")
# header
print("""       
#    name
1    net_rx_action
2    netif_receive_skb
3    ip_rcv
4    udp_rcv
5    sock_def_readable

Minus number means function returns corresponding to its number.
""")


#define PACKET_HOST		0		/* To us		*/
#define PACKET_BROADCAST	1		/* To all		*/
#define PACKET_MULTICAST	2		/* To group		*/
#define PACKET_OTHERHOST	3		/* To someone else 	*/
#define PACKET_OUTGOING		4		/* Outgoing of any type */
#define PACKET_LOOPBACK		5		/* MC/BRD frame looped back */
#define PACKET_USER		6		/* To user space	*/
#define PACKET_KERNEL		7		/* To kernel space	*/
#/* Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space */
#define PACKET_FASTROUTE	6		/* Fastrouted frame	*/


print("%18s %16s %8s %8s %12s %8s %12s" % ("TIME(s)", "COMM", "TYPE", "TGID", "NET LAYER", "PAYLOAD", "DATA LENGTH"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
#    if start == 0:
#            start = event.ts
#    time_s = (float(event.ts - start)) / 1000000000
    print("%18.0f %16s %8d %8d %12d %8d %12d" % (event.ts, event.comm, event.type,#event.pid&(0x00000000FFFFFFFF),
        event.pid >> 32, event.net_layer, event.len, event.data_len))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()
