#!/usr/bin/python
from bcc import BPF

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

////////////////////////////// LAYER 5 CONTEXT ////////////////////////////////
int uprobe (struct pt_regs *ctx){
    struct data_t data = {};
    pid_comm_ts(&data);
    data.net_layer = LAYER5|0x00;
 events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int uretprobe (struct pt_regs *ctx){
    struct data_t data = {};
    data.net_layer = LAYER5|0x01;
    pid_comm_ts(&data);
 events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


////////////////////////////// LAYER 4 CONTEXT ////////////////////////////////
BPF_HASH(start, struct sock *);
BPF_HASH(end, u64 , struct data_t);

int _sock_send(struct pt_regs *ctx)
{
    struct socket *sock;
    u64 ts;

    sock = (struct socket *)PT_REGS_PARM1(ctx); 
    struct sock *sk = sock->sk;

    ts = bpf_ktime_get_ns();
    start.update(&sk, &ts);
    return 0;
}

int _sock_recv_return(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct data_t 	*tmp_data;

    int len;
    u64 pid;

    len = PT_REGS_RC(ctx);
    if (len < 0) {
        return 0;
    }
    pid = bpf_get_current_pid_tgid();

    tmp_data = end.lookup(&pid);
    if (tmp_data) {
        data = *tmp_data;
    }

    data.ts = bpf_ktime_get_ns();
    data.net_layer = RETURN_FUN | LAYER4 | 0x10;
    if (data.s_port || data.d_port || data.s_ip || data.d_ip) {
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int skb_recv_udp(struct pt_regs *ctx)
{
    struct data_t data = {};

    struct sk_buff *skb;
    struct udphdr * uh;
    struct iphdr * iph;
    u8 pkt_type;
    skb = (struct sk_buff *)PT_REGS_RC(ctx);

    pkt_type = *(skb->__pkt_type_offset);
    pkt_type = 0x07 & pkt_type;
    data.type = pkt_type;

    uh = (struct udphdr *) (skb->head + skb->transport_header);
    iph = (struct iphdr *) (skb->head + skb->network_header);

    data.csum = uh->check;
    data.len = skb->len;
    data.d_port = uh->dest;
    data.s_port = uh->source;
    data.d_ip = iph->daddr;
    data.s_ip = iph->saddr;

    pid_comm_ts(&data);
    end.update(&data.pid, &data);

    // data.net_layer = RETURN_FUN | LAYER4 | 0x11;
    // events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


////////////////////////////// LAYER 3 CONTEXT ////////////////////////////////
int ip_send_skb (struct pt_regs *ctx)
{
    struct sk_buff *skb;
    struct udphdr * uh;
    struct iphdr * iph;
    struct data_t data = {};
    u8 pkt_type;
    u64 *l4_ts;

    pid_comm_ts(&data);
    skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    pkt_type = *(skb->__pkt_type_offset);
    pkt_type = 0x07 & pkt_type;
    data.type = pkt_type;

    uh = (struct udphdr *) (skb->head + skb->transport_header);
    iph = (struct iphdr *) (skb->head + skb->network_header);

    struct sock *sk;
    sk = skb->sk;
    l4_ts = start.lookup(&sk);
    if (l4_ts) {
        data.send_start_ts = *l4_ts;
    }
    start.delete(&sk);

    data.csum = uh->check;
    data.len = (skb->len);
    data.d_port = uh->dest;
    data.s_port = uh->source;
    data.d_ip = iph->daddr;
    data.s_ip = iph->saddr;

    data.net_layer = LAYER3 | 0x00;
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)

b.attach_kprobe( event="sock_sendmsg", fn_name="_sock_send")
b.attach_kprobe( event="ip_send_skb", fn_name="ip_send_skb")

b.attach_kretprobe( event="__skb_recv_udp", fn_name="skb_recv_udp") 
b.attach_kretprobe(event="sock_recvmsg", fn_name="_sock_recv_return")

#b.attach_uprobe(name="/home/alvin/workspace/opensplice/install/HDE/x86_64.linux/lib/libddskernel.so", sym="v_groupWrite", fn_name="uprobe")
#b.attach_uretprobe(name="/home/alvin/workspace/opensplice/install/HDE/x86_64.linux/lib/libddskernel.so", sym="v_groupWrite", fn_name="uretprobe")


# HEADER
print("%18s, %16s, %8s, %8s, %10s, %10s, %8s, %16s, %10s, %16s, %6s, %10s,   %10s" % 
     ("TIME(ns)", "COMM", "TYPE", "TGID", "TID", "NET LAYER", "PAYLOAD", "HOST_IP", "HOST_PORT", "IP", "PORT", "CHECKSUM", "START TIME(ns)"))

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

    print("%18d, %16s, %8d, %8d,   %8d, %10x, %8d, %16s, %10s, %16s, %6s, %10d,   %10d" % 
         (event.ts, event.comm, event.type, pid, tid, event.net_layer, event.len, s_ip, s_port, d_ip, d_port, event.csum, event.send_start_ts))

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

