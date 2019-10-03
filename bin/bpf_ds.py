#!/usr/bin/python
from bcc import BPF
from bpf_ds_layer3 import bpf_layer3_txt
from bpf_ds_layer4 import bpf_layer4_txt
from bpf_ds_layer5 import bpf_layer5_txt

# define BPF program
prog = """
#include <linux/sched.h>
#include <net/inet_sock.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/ip.h>

#define LAYER2 0x200
#define LAYER3 0x300
#define LAYER4 0x400
#define LAYER5 0x500
#define RETURN_FUN 0x1000

struct data_t {
    u64 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];

    u64 send_start_ts;
    unsigned int net_layer;
    u8 type;

    u32 d_ip, s_ip;
    u16 d_port, s_port;
    u16 csum;
    int len;  

};
BPF_PERF_OUTPUT(events);

static void pid_comm_ts(struct data_t* data) {
    data->pid = bpf_get_current_pid_tgid();
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&(data->comm), sizeof(data->comm));
}

int rx_action(struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = LAYER2|0x00;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int return_rx_action(struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = RETURN_FUN|LAYER2;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int netif_receive(struct pt_regs *ctx) {
    struct data_t data = {};
    struct sk_buff *skb;
    skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    data.len = skb->len;
    data.len = skb->data_len;
    data.type = (*skb).pkt_type;

    pid_comm_ts(&data);
    data.net_layer = 2;

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

int ip_r(struct pt_regs *ctx) {
    struct data_t data = {};
    struct sk_buff *skb;
    skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    data.len = skb->len;
    data.len = skb->data_len;
    data.type = (*skb).pkt_type;
    
    pid_comm_ts(&data);
    data.net_layer = 3;

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

int udp_r(struct pt_regs *ctx) {
    struct data_t data = {};
    struct sk_buff *skb;
    skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    data.len = skb->len;
    data.len = skb->data_len;
    data.type = (*skb).pkt_type;

    pid_comm_ts(&data);
    data.net_layer = 4;

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

int data_ready(struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = 5;

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

%s // LAYER 5 CONTEXT

/*  FUNCTION                KPROBE

    sock_sendmsg    :       sock_send
    r sock_sendmsg  :       _sock_send_return

    udp_sendmsg     :       udp_send_msg

    sock_recvmsg    :       sock_recv
    r sock_recvmsg  :       _sock_recv_return
 
*/
%s // LAYER 4 CONTEXT
 
%s // LAYER 3 CONTEXT
""" % (bpf_layer5_txt, bpf_layer4_txt, bpf_layer3_txt)

# load BPF program
b = BPF(text=prog)

b.attach_kprobe( event="sock_sendmsg", fn_name="_sock_send")


#b.attach_kprobe( event="udp_sendmsg", fn_name="udp_send_msg")
b.attach_kprobe( event="ip_send_skb", fn_name="ip_send_skb")
#b.attach_kretprobe( event="sock_sendmsg", fn_name="_sock_send_return")

b.attach_kretprobe( event="__skb_recv_udp", fn_name="skb_recv_udp") 
#b.attach_kprobe(event="sock_recvmsg", fn_name="sock_recv")
b.attach_kretprobe(event="sock_recvmsg", fn_name="_sock_recv_return")

#b.attach_uprobe(name="/home/alvin/workspace/opensplice/install/HDE/x86_64.linux/lib/libddskernel.so", sym="v_groupWrite", fn_name="uprobe")
#b.attach_uretprobe(name="/home/alvin/workspace/opensplice/install/HDE/x86_64.linux/lib/libddskernel.so", sym="v_groupWrite", fn_name="uretprobe")


#b.attach_kprobe(event="net_rx_action", fn_name="rx_action")
#b.attach_kretprobe(event="net_rx_action", fn_name="return_rx_action")



print("""       
#    FUNCTION NAME
1    net_rx_action
2    netif_receive_skb
3    ip_rcv
4    udp_rcv
5    sock_def_readable

""")

# HEADER
print("%18s, %16s, %8s, %8s, %10s, %10s, %8s, %16s, %10s, %16s, %6s, %10s" % 
     ("TIME(ns)", "COMM", "TYPE", "TGID", "TID", "NET LAYER", "PAYLOAD", "HOST_IP", "HOST_PORT", "IP", "PORT", "CHECKSUM"))

# process event
start = 0

def print_event(cpu, data, size):

    event = b["events"].event(data)

    pid = event.pid >> 32
    tid = event.pid & 0xFFFFFFFF

    d_ip = str((event.d_ip)       & 0x000000FF) + "." + \
         str((event.d_ip >>  8) & 0x000000FF) + "." + \
         str((event.d_ip >> 16) & 0x000000FF) + "." + \
         str((event.d_ip >> 24) & 0x000000FF)

    d_port = ((event.d_port >> 8) & 0x00FF) | ((event.d_port << 8) & 0xFF00)

    s_ip = str((event.s_ip)       & 0x000000FF) + "." + \
          str((event.s_ip >>  8) & 0x000000FF) + "." + \
          str((event.s_ip >> 16) & 0x000000FF)+ "." + \
          str((event.s_ip >> 24) & 0x000000FF)

    s_port = ((event.s_port >> 8) & 0x00FF) | ((event.s_port << 8) & 0xFF00)
        

    #if ((str(s_port)[0:2] =='74') or (str(d_port)[0:2] =='74')):
    print("%18d, %16s, %8d, %8d,   %8d, %10x, %8d, %16s, %10s, %16s, %6s, %10d, %10d" % 
         (event.ts, event.comm, event.type, pid, tid, event.net_layer, event.len, s_ip, s_port, d_ip, d_port, event.csum, event.send_start_ts))



# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt = 64*64)
while 1:
    b.perf_buffer_poll()


################################################################################

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


ipv4_is_multicast = """
static inline bool ipv4_is_multicast(__be32 addr)
{
	return (addr & htonl(0xf0000000)) == htonl(0xe0000000);
}
"""



#b.attach_kprobe(event="__netif_receive_skb_one_core", fn_name="netif_receive")

#b.attach_kprobe(event="ip_rcv", fn_name="ip_r")
#b.attach_kprobe(event="udp_rcv", fn_name="udp_r")
#b.attach_kprobe(event="sock_def_readable", fn_name="data_ready")

#b.attach_kprobe(event="__sys_recvfrom", fn_name="recv_from")
#b.attach_kprobe( event="__sys_sendto", fn_name="send_to")
#b.attach_kretprobe(event="__sys_recvfrom", fn_name="sock_recv")
#b.attach_kretprobe( event="__sys_sendto", fn_name="sock_send")


#b.attach_kretprobe(event="__netif_receive_skb_one_core", fn_name="return_netif_receive")
#b.attach_kretprobe(event="ip_rcv", fn_name="return_ip_r")
#b.attach_kretprobe(event="udp_rcv", fn_name="return_udp_r")
#b.attach_kprobe(event="sock_def_readable", fn_name="return_data_ready")
