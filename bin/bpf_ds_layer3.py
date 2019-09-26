#!/usr/bin/python

bpf_layer3_txt = """
int ip_send_skb (struct pt_regs *ctx) {
    struct sk_buff *skb;
    struct udphdr * uh;
    struct iphdr * iph;
    struct data_t data = {};
    pid_comm_ts(&data);
    skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    uh = (struct udphdr *) (skb->head + skb->transport_header);
    iph = (struct iphdr *) (skb->head + skb->network_header);

    data.csum = uh -> check;
    data.len = skb -> data_len;
    data.d_port = uh ->dest;
    data.s_port = uh ->source;
    data.d_ip = iph -> saddr;
    data.s_ip = iph -> daddr;



data.net_layer = LAYER3|0x00;
    events.perf_submit(ctx, &data, sizeof(data));
    

    return 0;

}


"""
