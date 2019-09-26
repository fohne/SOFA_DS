#!/usr/bin/python

bpf_layer4_txt = """
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


///////////////////////////////////////////////////////////////////////////

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


"""

