#!/usr/bin/python

bpf_layer4_txt = """
struct pid_payload {
    u64 pid;
    u16 payload; 
};

BPF_HASH(start, struct sock *);
BPF_HASH(end, u64 , struct data_t);

int _sock_send(struct pt_regs *ctx) {
    struct data_t data = {};
    struct socket * sock;

    struct msghdr *msg;
    struct sockaddr_in  skaddr;

    sock = (struct socket *)PT_REGS_PARM1(ctx); 
    struct sock *sk = sock->sk;
//data.sock_maddr = (u64)sk;

    struct inet_sock *inet =  (struct inet_sock *)sk;
    data.s_ip = inet -> inet_saddr;
    data.s_port = inet -> inet_sport;

    msg = (struct msghdr *)PT_REGS_PARM2(ctx); 
    size_t len = msg->msg_iter.count;
    void * pmsg_name =  msg->msg_name;
    bpf_probe_read(&skaddr, sizeof(struct sockaddr), pmsg_name);




    data.d_port = skaddr.sin_port;
    data.d_ip = skaddr.sin_addr.s_addr;
    data.len = len;
    pid_comm_ts(&data);
    data.net_layer = LAYER4|0x00;
start.update(&sk, &data.ts);
    //events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int _sock_send_return (struct pt_regs *ctx) {
    struct data_t data = {};

    pid_comm_ts(&data);
    data.net_layer = RETURN_FUN|LAYER4|0x00;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int udp_send_msg(struct pt_regs *ctx) {

    struct sockaddr_in  skaddr;
    struct inet_sock * inet;
    struct msghdr* msg;

    struct data_t data = {};

    size_t len;

    inet = (struct inet_sock *)PT_REGS_PARM1(ctx);
    msg = (struct msghdr *)PT_REGS_PARM2(ctx);    

    pid_comm_ts(&data);
//data.sock_maddr = (u64)inet;



    data.s_ip = inet->inet_saddr;
    data.s_port = inet->inet_sport;
    len = msg->msg_iter.count;

    void * pmsg_name =  msg->msg_name;
    bpf_probe_read(&skaddr, sizeof(struct sockaddr), pmsg_name);

    data.d_port = skaddr.sin_port;
    data.d_ip = skaddr.sin_addr.s_addr;
    data.len = len;
    data.net_layer = LAYER4|0x01;
    


    events.perf_submit(ctx, &data, sizeof(data));


    return 0;
}




///////////////////////////////////////////////////////////////////////////

int sock_recv(struct pt_regs *ctx) {
    struct data_t data = {};
    struct msghdr *msg;
    struct sockaddr_in skaddr;
    struct socket * sock;

    sock = (struct socket *)PT_REGS_PARM1(ctx); 
    struct sock *sk = sock->sk;
    struct inet_sock *inet = (struct inet_sock *)sk;
    data.d_ip = inet -> inet_saddr;
    data.d_port = inet -> inet_dport;

    msg = (struct msghdr *)PT_REGS_PARM2(ctx);  
    void * pmsg_name =  msg->msg_name;
    bpf_probe_read(&skaddr, sizeof(struct sockaddr), pmsg_name);


//    data.s_ip = skaddr.sin_addr.s_addr; // if 0.0.0.0, receive any ip source.
//    data.s_port = skaddr.sin_port; // service port number

    pid_comm_ts(&data);
    data.net_layer = LAYER4|0x10;

    events.perf_submit( ctx, &data, sizeof(data));
    return 0;
}


int _sock_recv_return(struct pt_regs *ctx) {
    struct data_t data = {};
    struct data_t 	*tmp_data;

    int len;

    len = PT_REGS_RC(ctx);
    if (len < 0) {
        return 0;
    }
    data.len = len;

data.pid = bpf_get_current_pid_tgid();

    tmp_data = end.lookup(&data.pid);
    if (tmp_data){
    data = *tmp_data;
}
    data.ts = bpf_ktime_get_ns();

    data.net_layer = RETURN_FUN|LAYER4|0x10;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}



//struct sk_buff *__skb_recv_udp(struct sock *sk, unsigned int flags, int noblock, int *off, int *err)

int skb_recv_udp(struct pt_regs *ctx) {
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

    data.csum = uh -> check;
    data.len = skb -> len;
    data.d_port = uh ->dest;
    data.s_port = uh ->source;
    data.d_ip = iph -> daddr;
    data.s_ip = iph -> saddr;

    pid_comm_ts(&data);

    end.update(&data.pid,&data);
    data.net_layer = RETURN_FUN|LAYER4|0x11;



  //  events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


"""

