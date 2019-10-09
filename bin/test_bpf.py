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

#define LAYER2 0x200
#define LAYER3 0x300
#define LAYER4 0x400
#define LAYER5 0x500
#define RETURN_FUN 0x80

struct data_t {
    u64 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];

    unsigned char net_layer;
    u8 type;

    u32 ip, hip;
    u16 port, hport;

    int len;  
    char data[100];
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
    data.net_layer = 1;

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

////////////////////////////////////////////////////////////////////////////////////////

int _sock_send(struct pt_regs *ctx) {
    struct data_t data = {};
    struct socket * sock;

    struct msghdr *msg;
    struct sockaddr_in  skaddr;

    sock = (struct socket *)PT_REGS_PARM1(ctx); 
    struct sock *sk = sock->sk;
    struct inet_sock *inet =  (struct inet_sock *)sk;
    data.hip = inet -> inet_saddr;
    data.hport = inet -> inet_sport;

    msg = (struct msghdr *)PT_REGS_PARM2(ctx); 
    size_t len = msg->msg_iter.count;
    void * pmsg_name =  msg->msg_name;
    bpf_probe_read(&skaddr, sizeof(struct sockaddr), pmsg_name);

 // u8* user_buff = (u8*)((msg->msg_iter).iov)->iov_base;

 // bpf_probe_read_user(data.data, 100, user_buff);


    data.port = skaddr.sin_port;
    data.ip = skaddr.sin_addr.s_addr;
    data.len = len;
    pid_comm_ts(&data);
    data.net_layer = LAYER4|0x00;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int _sock_send_return (struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = RETURN_FUN|LAYER4|0x00;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int sock_recv(struct pt_regs *ctx) {
    struct data_t data = {};
    struct msghdr *msg;
    struct sockaddr_in skaddr;
    struct socket * sock;

    sock = (struct socket *)PT_REGS_PARM1(ctx); 
    struct sock *sk = sock->sk;
    struct inet_sock *inet = (struct inet_sock *)sk;
    data.hip = inet -> inet_saddr;
    data.port = inet -> inet_dport;

    msg = (struct msghdr *)PT_REGS_PARM2(ctx);  
    void * pmsg_name =  msg->msg_name;
    bpf_probe_read(&skaddr, sizeof(struct sockaddr), pmsg_name);


    //u8* user_buff = (u8*)((msg->msg_iter).iov)->iov_base;

    //bpf_probe_read(data.data, 100, user_buff);

    data.ip = skaddr.sin_addr.s_addr; // if 0.0.0.0, receive any ip source.
    data.hport = skaddr.sin_port; // service port number

    pid_comm_ts(&data);
    data.net_layer = LAYER4|0x01;

    events.perf_submit( ctx, &data, sizeof(data));
    return 0;
}


int _sock_recv_return(struct pt_regs *ctx) {
    struct data_t data = {};
    int len;

    len = PT_REGS_RC(ctx);
    data.len = len;
    pid_comm_ts(&data);
    data.net_layer = RETURN_FUN|LAYER4|0x01;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int udp_send_msg(struct pt_regs *ctx) {

 // struct inet_sock *inet ;
 // struct udp_sock *up = udp_sk(sk);


    struct msghdr* msg;
    struct sockaddr_in  skaddr;
    struct data_t data = {};

 // int = (struct inet_sock *)PT_REGS_PARM1(ctx);
 // inet->inet_saddr;
    msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    size_t _len = PT_REGS_PARM3(ctx);

 // u8* user_buff = (u8*)((msg->msg_iter).iov)->iov_base;

 // bpf_probe_read(data.data, 100, user_buff);

    size_t len = msg->msg_iter.count;
    void * pmsg_name =  msg->msg_name;
    bpf_probe_read(&skaddr, sizeof(struct sockaddr), pmsg_name);

    data.port = skaddr.sin_port;
    data.ip = skaddr.sin_addr.s_addr;
    data.len = len;
    pid_comm_ts(&data);
    data.net_layer = LAYER4|0x00;

    events.perf_submit(ctx, &data, sizeof(data));


    return 0;
}

int skb_recv_udp(struct pt_regs *ctx) {
    struct data_t data = {};
    struct sk_buff *skb;


    skb = (struct sk_buff *)PT_REGS_RC(ctx);
    data.len = skb->len;
    pid_comm_ts(&data);
    data.net_layer = LAYER4|0x01;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
} 

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


int uprobeeo (struct pt_regs *ctx){
    struct data_t data = {};
    pid_comm_ts(&data);
    data.net_layer = LAYER2|0x00;
 events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int uretprobeeo (struct pt_regs *ctx){
    struct data_t data = {};
    data.net_layer = LAYER2|0x01;
    pid_comm_ts(&data);
 events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)

b.attach_kprobe( event="sock_sendmsg", fn_name="_sock_send")
#b.attach_kprobe( event="udp_sendmsg", fn_name="udp_send_msg")
#b.attach_kretprobe( event="__skb_recv_udp", fn_name="skb_recv_udp") # Not working
b.attach_kretprobe( event="sock_sendmsg", fn_name="_sock_send_return")

b.attach_kprobe(event="sock_recvmsg", fn_name="sock_recv")
#b.attach_kretprobe(event="sock_recvmsg", fn_name="_sock_recv_return")
#b.attach_uprobe(name="/home/alvin/workspace/opensplice/install/HDE/x86_64.linux/lib/libddskernel.so", sym="v_groupWrite", fn_name="uprobe")
#b.attach_uretprobe(name="/home/alvin/workspace/opensplice/install/HDE/x86_64.linux/lib/libddskernel.so", sym="v_groupWrite", fn_name="uretprobe")


#b.attach_kprobe(event="net_rx_action", fn_name="rx_action")
#b.attach_kprobe(event="__netif_receive_skb_one_core", fn_name="netif_receive")

#b.attach_kprobe(event="ip_rcv", fn_name="ip_r")
#b.attach_kprobe(event="udp_rcv", fn_name="udp_r")
#b.attach_kprobe(event="sock_def_readable", fn_name="data_ready")

#b.attach_kprobe(event="__sys_recvfrom", fn_name="recv_from")
#b.attach_kprobe( event="__sys_sendto", fn_name="send_to")
#b.attach_kretprobe(event="__sys_recvfrom", fn_name="sock_recv")
#b.attach_kretprobe( event="__sys_sendto", fn_name="sock_send")

#b.attach_kretprobe(event="net_rx_action", fn_name="return_rx_action")
#b.attach_kretprobe(event="__netif_receive_skb_one_core", fn_name="return_netif_receive")
#b.attach_kretprobe(event="ip_rcv", fn_name="return_ip_r")
#b.attach_kretprobe(event="udp_rcv", fn_name="return_udp_r")
#b.attach_kprobe(event="sock_def_readable", fn_name="return_data_ready")


print("""       
#    FUNCTION NAME
1    net_rx_action
2    netif_receive_skb
3    ip_rcv
4    udp_rcv
5    sock_def_readable

""")

# HEADER
print("%18s, %16s, %8s, %8s, %10s, %10s, %8s, %16s, %10s, %16s, %6s" % 
     ("TIME(ns)", "COMM", "TYPE", "TGID", "TID", "NET LAYER", "PAYLOAD", "HOST_IP", "HOST_PORT", "IP", "PORT"))

# process event
start = 0

def print_event(cpu, data, size):

    event = b["events"].event(data)

    pid = event.pid >> 32
    tid = event.pid & 0xFFFFFFFF

    ip = str((event.ip)       & 0x000000FF) + "." + \
         str((event.ip >>  8) & 0x000000FF) + "." + \
         str((event.ip >> 16) & 0x000000FF) + "." + \
         str((event.ip >> 24) & 0x000000FF)

    port = ((event.port >> 8) & 0x00FF) | ((event.port << 8) & 0xFF00)

    hip = str((event.hip)       & 0x000000FF) + "." + \
          str((event.hip >>  8) & 0x000000FF) + "." + \
          str((event.hip >> 16) & 0x000000FF)+ "." + \
          str((event.hip >> 24) & 0x000000FF)

    hport = ((event.hport >> 8) & 0x00FF) | ((event.hport << 8) & 0xFF00)
    a = []
    for i in event.data:
        a.append(i)
        

    #if (str(port)[0:2] =='74'):
    print("%18d, %16s, %8d, %8d, %8d, %10x, %8d, %16s, %10s, %16s, %6s" % 
         (event.ts, event.comm, event.type, pid, tid, event.net_layer, event.len, hip, hport, ip, port))



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
