#!/usr/bin/python

bpf_layer4_txt = """

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

///////////////////////////////////////////////////////////////////////////


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

"""

