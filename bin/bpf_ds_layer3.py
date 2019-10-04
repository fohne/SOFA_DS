#!/usr/bin/python

bpf_layer3_txt = """
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
