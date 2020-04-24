#!/usr/bin/python
from bcc import BPF

intrucode="""
BPF_PERF_OUTPUT(events);

//#define DEBUG 

#define    DDS_RECORD     1
#define   SOCK_RECORD     2

#define FID_CREATE_TOPIC      1
#define FID_CREATE_DDSWRITER  2
#define FID_CREATE_DDSREADER  3
#define FID_DDSWRITER_WRITE   4
#define FID_WRITER_WRITE      5
#define FID_RTPS_WRITE        6

#define FID_SEND_MSG         21
#define FID_IP_SEND          22
#define FID_RECV_UDP         23
#define FID_RECV_MSG         24

#ifdef asm_inline
    #undef asm_inline
    #define asm_inline asm
#endif

#include <linux/sched.h>
#include <linux/stddef.h>

#include <net/inet_sock.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/ip.h>

typedef struct topic_info_t { 
    char name[64];
} topic_info;
BPF_HASH(tName_map, u64, topic_info);

typedef struct v_gid_t {
    u32 systemId;
    u32 localId;
    u32 serial;
} v_gid;

typedef struct v_message_t {
    u32    v_node;
    u64    allocTime;
    u32    sequenceNumber;
    u32    transactionId;
    u64    writeTime;
    v_gid  writerGID;
    v_gid  writerInstanceGID;
    u64    qos;
} v_message;

typedef struct trace_id_t {
    v_gid  gid;
    u32    seqNum;
} traceId;
BPF_HASH(traceId_map, u64, traceId);

typedef struct bpf_data_t {
    u64  ts;
    u64  ets;
    u64  pid;
    char comm[TASK_COMM_LEN];
    char tName[64];

    u8   recordType;
    u16  fun_ID;
    u8   fun_ret; 

    u64  arg1;
    u64  arg2;
    u64  arg3;
    u64  arg4;
    u64  arg5;
    u64  arg6;
    u64  ret;
    u64  link;

    u64  seqNum;
    u32  gid_sys;
    u32  gid_local;
    u32  gid_seria;
} bpf_data;


BPF_HASH(ts_map, u64, u64);

int Start_TS (struct pt_regs *ctx){
    u64 pid = bpf_get_current_pid_tgid();
    u64  ts = bpf_ktime_get_ns();

    ts_map.update(&pid, &ts);

    return 0;
}

int End_TS (struct pt_regs *ctx){
    u64   pid = bpf_get_current_pid_tgid();
    u64* s_ts = ts_map.lookup(&pid);
    u64  e_ts = bpf_ktime_get_ns();

    return 0;
}
/*************************************************************************************************/
/**                                                                                             **/
/**                     This part record OpenSplice DDS topic information.                      **/
/**                                                                                             **/
/*************************************************************************************************/

/* =======================================================================
    Instrumented function:         DDS_DomainParticipant_create_topic
   ======================================================================= */ 
int T_GetTopicName(struct pt_regs *ctx) { // 2:topic name; 3: type_name; ret: topic pointer
 
    topic_info topic   = {};
    u64        tName_p = PT_REGS_PARM2(ctx);
    u64        pid     = bpf_get_current_pid_tgid();

    bpf_probe_read_str(topic.name, 64, (const char *)tName_p);
    tName_map.update(&pid, &topic);

    return 0;
}

int T_MapTopic2TopicName(struct pt_regs *ctx){ // ret: topic

    u64               pid = bpf_get_current_pid_tgid();
    topic_info*  t_info_p = tName_map.lookup(&pid);


    if (t_info_p) {
        topic_info   topic = *t_info_p;

        u64 topic_p = PT_REGS_RC(ctx);

        tName_map.update(&topic_p, &topic);
        tName_map.delete(&pid);

    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ret = topic_p;

        data.ts  = bpf_ktime_get_ns();
        data.pid = pid;
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID = FID_CREATE_TOPIC;
        data.fun_ret = 1;
        bpf_probe_read_str(data.tName, 64, (const char *)t_info_p->name);

        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }

    return 0;
}

/* =======================================================================
     Instrumented function:         DDS_Publisher_create_datawriter
   ======================================================================= */ 
int W_MapPID2Topic(struct pt_regs *ctx) { // 2:topic; ret: writer
    u64          topic_p = PT_REGS_PARM2(ctx);
    topic_info* t_info_p = tName_map.lookup(&topic_p);

    if (t_info_p) {
        topic_info   topic = *t_info_p;


        u64 pid = bpf_get_current_pid_tgid();
        tName_map.update(&pid, &topic);
    }

    return 0;
}

int W_MapWriter2TopicName(struct pt_regs *ctx) { // 2:topic; ret: writer
    u64 pid = bpf_get_current_pid_tgid();

    topic_info* t_info_p;
    t_info_p = tName_map.lookup(&pid);

    if (t_info_p) {
        topic_info   topic = *t_info_p;


        u64 writer = PT_REGS_RC(ctx);
        tName_map.update(&writer, &topic);
        tName_map.delete(&pid);
    #ifdef DEBUG
        //topic_info  topic = *t_info_p;

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = pid;
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = FID_CREATE_DDSWRITER;
        data.fun_ret = 1;
        bpf_probe_read_str(data.tName, 64, t_info_p->name);
        data.ret = writer;
        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }

    return 0;
}

/* =======================================================================
     Instrumented function:         v_writerNew
   ======================================================================= */ 
int W_MapVWriter2TopicName (struct pt_regs *ctx) { //ret: v_writer
    u64 pid = bpf_get_current_pid_tgid();

    topic_info* t_info_p;
    t_info_p = tName_map.lookup(&pid);

    if (t_info_p) {
        topic_info   topic = *t_info_p;

        u64 v_writer = PT_REGS_RC(ctx);
        tName_map.update(&v_writer, &topic);

    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = pid;
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = 20;
        data.fun_ret = 1;
        bpf_probe_read_str(data.tName, 64, t_info_p->name);
        data.ret = v_writer;
        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }

    return 0;
}

/* =======================================================================
    Instrumented function:         DDS_Subscriber_create_datareader
   ======================================================================= */ 
int R_MapPID2Topic(struct pt_regs *ctx) { // 2:topic; ret: reader
    u64          topic_p = PT_REGS_PARM2(ctx);
    topic_info* t_info_p = tName_map.lookup(&topic_p);

    if (t_info_p) {
        topic_info   topic = *t_info_p;

        u64 pid = bpf_get_current_pid_tgid();
        tName_map.update(&pid, &topic);
    }

    return 0;
}

int R_MapReader2TopicName(struct pt_regs *ctx) { // 2:topic; ret: reader_p
    u64              pid = bpf_get_current_pid_tgid();
    topic_info* t_info_p = tName_map.lookup(&pid);

    if (t_info_p) {
        topic_info   topic = *t_info_p;

        u64 reader = PT_REGS_RC(ctx);
        tName_map.update(&reader, &topic);
        tName_map.delete(&pid);
    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = pid;
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = FID_CREATE_DDSREADER;
        data.fun_ret = 1;
        bpf_probe_read_str(data.tName, 64, t_info_p->name);
        data.ret = reader;
        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }

    return 0;
}

/*************************************************************************************************/
/**                                                                                             **/
/**                This part record write/read and its corresponding v_message.                 **/
/**                                                                                             **/
/*************************************************************************************************/

/* =======================================================================
    Instrumented function:         DDS_DataWriter_write
   ======================================================================= */ 
int DDSWrite_Start(struct pt_regs *ctx) {
    u64           writer = PT_REGS_PARM1(ctx); // DDS_DataWriter



    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = FID_DDSWRITER_WRITE;
        data.fun_ret = 0;


       // events.perf_submit(ctx, &data, sizeof(data));
    #endif
    
    return 0;
}

/* =======================================================================
    Instrumented function:         writerWrite
   ======================================================================= */ 
int W_MapVMess2GID (struct pt_regs *ctx) {

    u64         v_writer = PT_REGS_PARM1(ctx);
    topic_info* t_info_p = tName_map.lookup(&v_writer);

    if (t_info_p) {
        topic_info   topic = *t_info_p;

        u64        v_mess_p = PT_REGS_PARM3(ctx);
        v_message  v_mess;
        bpf_probe_read(&v_mess, sizeof(v_message), (const void *) v_mess_p);
        tName_map.update(&v_mess_p, &topic);

        traceId trace_id;
        bpf_probe_read(&trace_id.gid, sizeof(v_gid), (const void *) v_mess_p + offsetof(v_message, writerGID));
        bpf_probe_read(&trace_id.seqNum, sizeof(u32), (const void *) v_mess_p + offsetof(v_message, sequenceNumber));
        traceId_map.update(&v_mess_p, &trace_id);

    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = FID_WRITER_WRITE;
        data.fun_ret = 0;
        bpf_probe_read_str(data.tName, 64, t_info_p->name);

        data.gid_sys   = v_mess.writerGID.systemId;
        data.gid_local = v_mess.writerGID.localId;
        data.gid_seria = v_mess.writerGID.serial;
        data.seqNum = v_mess.sequenceNumber;

        data.arg1 = trace_id.gid.systemId;
        data.arg2 = trace_id.gid.localId;
        data.arg3 = trace_id.gid.serial;
        data.link = trace_id.seqNum;

        data.ret = v_mess_p;
        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }
    return 0;
}

/* =======================================================================
    Instrumented function:         rtps_Write
   ======================================================================= */ 
int Map_GID2Packet(struct pt_regs *ctx){ // (xp, &sender, message)
    bpf_data data = {};
    u64       pid = bpf_get_current_pid_tgid();

    v_gid* gid_p = (v_gid*)PT_REGS_PARM2(ctx);
    v_gid   gid = *gid_p; 
    u64     v_mess_p = PT_REGS_PARM3(ctx); //v_message

    topic_info* t_info_p = tName_map.lookup(&v_mess_p);
    if (t_info_p) {
        topic_info   topic = *t_info_p;

        bpf_probe_read_str(data.tName, 64, t_info_p->name);

        tName_map.update(&pid, &topic);
        tName_map.delete(&v_mess_p);
     }

    traceId * trace_id_p = traceId_map.lookup(&v_mess_p);
    if (trace_id_p) {
        traceId trace_id = *trace_id_p;
        data.arg1 = trace_id.gid.systemId;
        data.arg2 = trace_id.gid.localId;
        data.arg3 = trace_id.gid.serial;
        data.link = trace_id.seqNum;
        traceId_map.update(&pid, &trace_id);
        traceId_map.delete(&v_mess_p);
    }
 
    data.ret = v_mess_p;
    data.recordType = DDS_RECORD;

    data.ts  = bpf_ktime_get_ns();
    data.pid = pid;
    bpf_get_current_comm(&(data.comm), sizeof(data.comm));
    data.fun_ID = FID_RTPS_WRITE;

    v_message v_mess;
    bpf_probe_read(&v_mess, sizeof(v_message), (const void *) v_mess_p);

    data.seqNum = v_mess.sequenceNumber;
    data.gid_sys = v_mess.writerGID.systemId;
    data.gid_local = v_mess.writerGID.localId;
    data.gid_seria = v_mess.writerGID.serial;

    v_gid gid2 ; 
    bpf_probe_read(&gid2, sizeof(v_gid), (const void *) v_mess_p + offsetof(v_message, writerGID));
    data.arg4 = gid.systemId;
    data.arg5 = gid.localId;
    data.arg6 = gid.serial;
  
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

/*************************************************************************************************/
/**                                                                                             **/
/**                kprobe for recording packets Tx/Rx messages                                  **/
/**                                                                                             **/
/*************************************************************************************************/

 //FID_SEND_MSG        
 //FID_IP_SEND 

/* =======================================================================
    Instrumented function:         sock_sendmsg
   ======================================================================= */
BPF_HASH(start, struct sock *, u64);
BPF_HASH(end, u64, bpf_data);

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

/* =======================================================================
    Instrumented function:         ip_send_skb
   ======================================================================= */
int ip_send_skb (struct pt_regs *ctx)
{

    bpf_data data = {};

    data.ts  = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(data.comm), sizeof(data.comm));

    data.fun_ID  = FID_IP_SEND;

    struct sk_buff*  skb = (struct sk_buff *) PT_REGS_PARM2(ctx);
    struct  udphdr*   uh = (struct udphdr *) (skb->head + skb->transport_header);
    struct   iphdr*  iph = (struct iphdr *) (skb->head + skb->network_header);
    struct    sock*   sk = skb->sk;

    u64 *l4_ts = start.lookup(&sk);
    if (l4_ts) {
        data.link = data.ts;
        data.ts   = *l4_ts;
        start.delete(&sk);
    }

    data.arg6 = 0x000000000000ffff & uh->check;
    data.arg5 = 0x000000000000ffff & skb->len;
    data.arg4 = 0x000000000000ffff & uh->dest;
    data.arg3 = 0x000000000000ffff & uh->source;
    data.arg2 = 0x00000000ffffffff & iph->daddr;
    data.arg1 = 0x00000000ffffffff & iph->saddr;

    topic_info* t_info_p = tName_map.lookup(&data.pid);
    if (t_info_p) {
        bpf_probe_read_str(data.tName, 64, t_info_p->name);
        tName_map.delete(&data.pid);
     }

    traceId * trace_id_p = traceId_map.lookup(&data.pid);
    if (trace_id_p) {
        traceId trace_id = *trace_id_p;
        data.gid_sys = trace_id.gid.systemId;
        data.gid_local = trace_id.gid.localId;
        data.gid_seria = trace_id.gid.serial;
        data.seqNum = trace_id.seqNum;

        traceId_map.delete(&data.pid);
    }

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

/* =======================================================================
    Instrumented function:         __skb_recv_udp
   ======================================================================= */
int skb_recv_udp_ret(struct pt_regs *ctx)
{
    struct sk_buff *skb;
    struct udphdr * uh;
    struct iphdr * iph;

    skb = (struct sk_buff *)PT_REGS_RC(ctx);

    uh = (struct udphdr *) (skb->head + skb->transport_header);
    iph = (struct iphdr *) (skb->head + skb->network_header);


    u64 pid = bpf_get_current_pid_tgid();

    bpf_data data = {};
    data.recordType = SOCK_RECORD;

    data.ts  = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(data.comm), sizeof(data.comm));

    data.fun_ID  = FID_RECV_UDP;
    data.fun_ret = 1;


    data.arg6 = 0x000000000000ffff & uh->check;
    data.arg5 = 0x000000000000ffff & skb->len;
    data.arg4 = 0x000000000000ffff & uh->dest;
    data.arg3 = 0x000000000000ffff & uh->source;
    data.arg2 = 0x00000000ffffffff & iph->daddr;
    data.arg1 = 0x00000000ffffffff & iph->saddr;
    end.update(&pid, &data);

    #ifdef DEBUG
        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    return 0;


}

/* =======================================================================
    Instrumented function:         sock_recvmsg
   ======================================================================= */
int _sock_recv_ret(struct pt_regs *ctx)
{
    int len = PT_REGS_RC(ctx);
    if (len < 0) {
        return 0;
    }

    bpf_data  data = {};
    u64 pid = bpf_get_current_pid_tgid();

    bpf_data* data_p = end.lookup(&pid);
    if (data_p) {
        data = *data_p;
        data.fun_ID  = FID_RECV_MSG;
        data.fun_ret = 1;
    }

    data.ts = bpf_ktime_get_ns();

    if (data.arg1 || data.arg2 || data.arg3 || data.arg4) {
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
"""

bpf = BPF(text=intrucode)

LIBPATH="/home/hermes/workspace/opensplice/install/HDE/x86_64.linux-dev/lib/"

# Topic information recording
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_DomainParticipant_create_topic", fn_name="T_GetTopicName")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_DomainParticipant_create_topic", fn_name="T_MapTopic2TopicName")
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Publisher_create_datawriter", fn_name="W_MapPID2Topic")
bpf.attach_uretprobe(name="%slibddskernel.so"%LIBPATH, sym="v_writerNew", fn_name="W_MapVWriter2TopicName")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Publisher_create_datawriter", fn_name="W_MapWriter2TopicName")
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Subscriber_create_datareader", fn_name="R_MapPID2Topic")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Subscriber_create_datareader", fn_name="R_MapReader2TopicName")


# Write/Read Records
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym= "DDS_DataWriter_write", fn_name="DDSWrite_Start")
#bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym= "DDS_DataWriter_write", fn_name="DDSWrite_End")
bpf.attach_uprobe(name="%slibddskernel.so"%LIBPATH, sym="writerWrite", fn_name="W_MapVMess2GID")
bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="rtps_write", fn_name="Map_GID2Packet")
#bpf.attach_uretprobe(name="%slibddsi2.so"%LIBPATH, sym="rtps_write", fn_name="cleanup_v")



bpf.attach_kprobe( event="sock_sendmsg", fn_name="_sock_send")
bpf.attach_kprobe( event="ip_send_skb", fn_name="ip_send_skb")

bpf.attach_kretprobe( event="__skb_recv_udp", fn_name="skb_recv_udp_ret") 
bpf.attach_kretprobe(event="sock_recvmsg", fn_name="_sock_recv_ret")


def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    if 1:
        print("%14d,%2d,%14d,%4d,%20s,%14s,%6d,%12d,%8d,%8d,%14d,%14d,%14d,%14d,%14d,%14d,%14d,%14s" % 
             (event.ts, event.recordType, event.pid, event.fun_ID, event.tName, event.comm, 
              event.seqNum, event.gid_sys, event.gid_local, event.gid_seria, 
event.arg1, event.arg2, event.arg3, 
event.arg4, event.arg5, event.arg6, event.link, 
              hex(event.ret)))  
    else:
        pass

bpf["events"].open_perf_buffer(print_event, page_cnt = 64*64)
while 1:
    bpf.perf_buffer_poll()

