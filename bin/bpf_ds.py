#!/usr/bin/python
from bcc import BPF

# define BPF program
prog = """
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <linux/sched.h>
#include <net/inet_sock.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/ip.h>


#define SEND       0x0000
#define RECV       0x0010
#define LAYER2     0x0200
#define LAYER3     0x0300
#define LAYER4     0x0400
#define LAYER5     0x0500
#define FUN_RETURN 0x1000



struct data_t {
    u64 ts;
    char comm[TASK_COMM_LEN];
    u8 type;
    u64 pid;
    u16 net_layer;
    int len;
    u32 s_ip, d_ip;
    u16 s_port, d_port;
    u16 csum;
    u64 l3_ts;
};
BPF_HASH(start, struct sock *);
BPF_HASH(w_ts,   u64, struct data_t, sizeof(struct data_t)  );
BPF_PERF_OUTPUT(events);

static void pid_comm_ts(struct data_t* data) {
    data->pid = bpf_get_current_pid_tgid();
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&(data->comm), sizeof(data->comm));
}

////////////////////////////// LAYER 5 CONTEXT ////////////////////////////////

////////////////////////////// LAYER 4 CONTEXT ////////////////////////////////

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
    data.net_layer = FUN_RETURN | LAYER4 | RECV;
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

    // data.net_layer = FUN_RETURN | LAYER4 | RECV |0x1;
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
        
        data.l3_ts = data.ts;
        data.ts = *l4_ts;
    }
    start.delete(&sk);

    data.csum = uh->check;
    data.len = (skb->len);
    data.d_port = uh->dest;
    data.s_port = uh->source;
    data.d_ip = iph->daddr;
    data.s_ip = iph->saddr;

    data.net_layer = LAYER3 | SEND;
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}



"""

# load BPF program
bpf = BPF(text=prog)

bpf.attach_kprobe( event="sock_sendmsg", fn_name="_sock_send")
bpf.attach_kprobe( event="ip_send_skb", fn_name="ip_send_skb")

bpf.attach_kretprobe( event="__skb_recv_udp", fn_name="skb_recv_udp") 
bpf.attach_kretprobe(event="sock_recvmsg", fn_name="_sock_recv_return")

#bpf.attach_uprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/examples/dcps/PingPong/c/standalone/libsac_pingpong_types.so", sym="pingpong_PP_string_msgDataWriter_write", fn_name="wuprobe")
#bpf.attach_uretprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/examples/dcps/PingPong/c/standalone/libsac_pingpong_types.so", sym="pingpong_PP_string_msgDataWriter_write", fn_name="wuretprobe")
#bpf.attach_uprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/examples/dcps/PingPong/c/standalone/libsac_pingpong_types.so", sym="pingpong_PP_string_msgDataReader_take", fn_name="ruprobe")
#bpf.attach_uretprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/examples/dcps/PingPong/c/standalone/libsac_pingpong_types.so", sym="pingpong_PP_string_msgDataReader_take", fn_name="wuretprobe")
#bpf.attach_uretprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/lib/libddskernel.so", sym="u_readerRead", fn_name="uretprobe")
#bpf.attach_uretprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/lib/libddskernel.so", sym="u_readerTake", fn_name="uretprobe")

#bpf.attach_uprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/lib/libdcpssac.so", sym= "DDS_DataWriter_write", fn_name="")
#bpf.attach_uprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/lib/libddskernel.so" , sym= "u_writerWrite", fn_name="")
#bpf.attach_uprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/lib/libddskernel.so" , sym="u_writeWithHandleAction", fn_name="")
#bpf.attach_uprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/lib/libdcpssac.so", sym="_DataWriterCopy", fn_name="")
#bpf.attach_uprobe(name="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/lib/libddskernel.so", sym="v_writerWrite", fn_name="")


#bpf.attach_uretprobe(name="/home/alvin/workspace/opensplice/install/HDE/x86_64.linux/lib/libddskernel.so", sym="v_groupWrite", fn_name="uretprobe")

def print_formatted_event(cpu, data, size):
    event = bpf["events"].event(data)
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

    print("%18d, %16s, %8d, %8d,   %8d, %10x, %8d, %16s, %10s, %16s, %6s, %10d,   %10d" % \
         (event.ts, event.comm, event.type, pid, tid, event.net_layer, event.len, s_ip,   \
          s_port, d_ip, d_port, event.csum, event.l3_ts))
    print("%d,%s,%d,%d,%x,%d,%d,%d,%d,%d,%d,%d\n" % \
         (event.ts, event.comm, event.type, event.pid, event.net_layer, event.len, event.s_ip,   \
          event.s_port, event.d_ip, event.d_port, event.csum, event.l3_ts))    

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    print("%d,%s,%d,%d,%x,%d,%d,%d,%d,%d,%d,%d" % \
         (event.ts, event.comm, event.type, event.pid, event.net_layer, event.len, event.s_ip,   \
          event.s_port, event.d_ip, event.d_port, event.csum, event.l3_ts))    


READABILITY = False

if READABILITY:
    print("%18s, %16s, %8s, %8s, %10s, %10s, %8s, %16s, %10s, %16s, %6s, %10s,   %10s" % \
         ("TIME(ns)", "COMM", "TYPE", "TGID", "TID", "NET LAYER", "PAYLOAD", "HOST_IP",  \
          "HOST_PORT", "IP", "PORT", "CHECKSUM", "SENDER L3 TS(ns)"))
    bpf["events"].open_perf_buffer(print_formatted_event, page_cnt = 64*64)

else:
    print("TIME(ns),COMM,TYPE,TGID_TID,NET LAYER,PAYLOAD,HOST_IP,HOST_PORT,IP,PORT,CHECKSUM,SENDER L3 TS(ns)")
    bpf["events"].open_perf_buffer(print_event, page_cnt = 64*64)

while 1:
    bpf.perf_buffer_poll()

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

