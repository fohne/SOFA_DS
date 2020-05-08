#!/usr/bin/python3
from bcc import BPF
import re
# define BPF program
prog = """
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <linux/sched.h>
BPF_PERF_OUTPUT(events);

BPF_HASH(start, u64,u64);
BPF_HASH(end, u64,u64);

typedef struct topic_info_s {
    char type_name[64];
    char topic_name[64];
    u64  tpoic_addr;
} topic_info;

typedef struct v_gid_s {
    u32 systemId;
    u32 localId;
    u32 serial;
} v_gid;

typedef struct v_message_s {
    u32    v_node;
    u64    allocTime;
    u32    sequenceNumber;
    u32    transactionId;
    u64    writeTime;
    v_gid  writerGID;
    v_gid  writerInstanceGID;
    u64    qos;
}v_message;

struct data_t {

    u64  ts;
    char comm[TASK_COMM_LEN];
    u16  fun_ID;
    u16  record_type;
    u8   fun_ret; 
    u64  pid;
    long writer;
    long xp;
    long fmsg;
    long dds_data;
    long writer_info;
    u64 v_msg;
    long s_d_data;
    int  sockfd;
    long msg;
    u32  seq;
    u64  topic;
    char topic_name[64];
    u32  gid_sys;
    u32  gid_local;
    u32  gid_seria;
};

typedef struct writerInfo_s {
     u64 writer;
     void* data;
} writerInfo;

BPF_HASH(writer_info_hash, u64, writerInfo);

BPF_HASH(topic_info_hash, u64, topic_info);
BPF_HASH(vmess_weiterinfo_hash, u64,writerInfo);
BPF_HASH(read_topic_hash, u64,u64);
static void pid_comm_ts(struct data_t* data) {
    data->pid = bpf_get_current_pid_tgid();
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&(data->comm), sizeof(data->comm));
}

int DDS_DataWriter_write (struct pt_regs *ctx){
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

int u_writerWrite(struct pt_regs *ctx){
    writerInfo w_info;
    u64 tmp;
    struct data_t data = {};
    pid_comm_ts(&data);
    u64 writer_info = (u64)PT_REGS_PARM3(ctx);
    data.fun_ID = 11;
    bpf_probe_read(&w_info,sizeof(w_info),(const void *)PT_REGS_PARM3(ctx));
    //data.writer_info = PT_REGS_PARM3(ctx);
    data.writer = (long)w_info.writer;
    data.dds_data = (long)w_info.data;

 //   topic_info* t_info_p;
   // topic_info  t_info = {};
    
  //  t_info_p = topic_info_hash.lookup(&(w_info.writer));
   // if (t_info_p) {
    //    t_info = *t_info_p;
     //     bpf_probe_read_str(data.topic_name, 64, (const void *)t_info.topic_name);        
  //  }

    writer_info_hash.update(&data.pid, &w_info); 
    data.writer_info = writer_info;   
    //events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int u_writeWithHandleAction(struct pt_regs *ctx){

    struct data_t data = {};
    pid_comm_ts(&data);

    data.fun_ID = 3;
 
    data.writer_info = PT_REGS_PARM3(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int _DataWriterCopy(struct pt_regs *ctx){

    struct data_t data = {};
    pid_comm_ts(&data);
    u64 writer_info = PT_REGS_PARM2(ctx);
    data.fun_ID = 12;

    data.writer_info = PT_REGS_PARM2(ctx);
    data.v_msg = PT_REGS_PARM3(ctx);
    data.v_msg -= 64;
    u64 v_msg = data.v_msg;
    writerInfo* w_info_p;
    writerInfo w_info;
    w_info_p = writer_info_hash.lookup(&data.pid);
    if (w_info_p) {
        w_info.writer= (long) w_info_p->writer;
        w_info.data= (void *) w_info_p->data;
        data.writer = (long) w_info_p->writer;
        data.dds_data = (long) w_info_p->data;
        writer_info_hash.delete(&data.pid);

        vmess_weiterinfo_hash.update(&v_msg,(u64 *) &w_info);    

        topic_info* t_info_p;
        topic_info  t_info = {};
    
        t_info_p = topic_info_hash.lookup(&w_info.writer);
        if (t_info_p) {
            t_info = *t_info_p;
              bpf_probe_read_str(data.topic_name, 64, (const void *)t_info.topic_name);        
        }
    }

  //  events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int v_writerWrite(struct pt_regs *ctx){

    struct data_t data = {};
    pid_comm_ts(&data);

    data.fun_ID = 5;
 
    data.v_msg = PT_REGS_PARM2(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;

}

int writerWrite(struct pt_regs *ctx){

    struct data_t data = {};
    pid_comm_ts(&data);
    v_message v_mess;
    data.fun_ID = 13;
    //data.writer = PT_REGS_PARM1(ctx); //v_writer
    data.v_msg = PT_REGS_PARM3(ctx);
    u64 msg_p = data.v_msg;
    bpf_probe_read(&v_mess, sizeof(v_message), (const void *)PT_REGS_PARM3(ctx));
    data.seq = v_mess.sequenceNumber;

    writerInfo* w_info_p;
    writerInfo w_info;
data.gid_sys = v_mess.writerGID.systemId;
data.gid_local = v_mess.writerGID.localId;
data.gid_seria = v_mess.writerGID.serial;
    w_info_p =(writerInfo*) vmess_weiterinfo_hash.lookup(&msg_p);
    if (w_info_p) {
        w_info = *w_info_p;
        data.writer = w_info.writer;
u64 tmp  = w_info_p->writer;
        topic_info* t_info_p;
        topic_info  t_info = {};
    
        t_info_p = (topic_info*) topic_info_hash.lookup(&tmp);
        if (t_info_p) {
            t_info = *t_info_p;
              bpf_probe_read_str(data.topic_name, 64, (const void *)t_info.topic_name);        
        }
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;

}

// enqueueSampleForResend(writer, instance, sample);  v_cacheWalk, groupInstanceWrite,V_groupInstanceWrite,
// v_groupWrite, groupWrite, 
// forwardMessageToNetwork, v_networkQueueWrite nwEntryWrite  v_networkReaderEntryWrite v_networkReaderWrite
// v_networkQueueWrite


int DDS_DomainParticipant_create_topic(struct pt_regs *ctx) { // 2:topic name; 3: type_name; ret: topic pointer
    struct data_t data = {};
    pid_comm_ts(&data);
    topic_info t_info = {};
    data.fun_ID = 1;
    data.fun_ret = 0;
    u64 pid = bpf_get_current_pid_tgid();
    u64 topic_name = PT_REGS_PARM2(ctx);
    u64 type_name = PT_REGS_PARM3(ctx);
    bpf_probe_read_str(t_info.topic_name, 64, (const void *)topic_name);
    bpf_probe_read_str(data.topic_name, 64, (const void *)topic_name);
    bpf_probe_read_str(t_info.type_name, 64, (const void *) type_name);
    topic_info_hash.update(&pid, &t_info);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int r_DDS_DomainParticipant_create_topic(struct pt_regs *ctx){ // ret: topic
    struct data_t data = {};
    pid_comm_ts(&data);
    topic_info* t_info_p;
    topic_info  t_info = {};
    u64 pid = bpf_get_current_pid_tgid();
    data.fun_ID = 1;
    data.fun_ret = 1;
    t_info_p = topic_info_hash.lookup(&pid);
    if (t_info_p) {
        t_info = *t_info_p;

        bpf_probe_read_str(data.topic_name, 64, (const void *)t_info.topic_name);

        topic_info_hash.delete(&pid);
        u64 topic;
        topic = PT_REGS_RC(ctx);
        t_info.tpoic_addr = topic;
        data.topic = topic;
        topic_info_hash.update(&topic, &t_info);
    events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
void DDS_Subscriber_create_datareader(struct pt_regs *ctx) { // 2:topic; ret: reader

    struct data_t data = {};
    pid_comm_ts(&data);
    data.fun_ID = 4;
    data.fun_ret = 0;
    u64 topic = PT_REGS_PARM2(ctx);
    data.topic = topic;
    topic_info* t_info_p;
    topic_info  t_info = {};
    t_info_p = topic_info_hash.lookup(&topic);


    if (t_info_p) {
        t_info = *t_info_p;
        u64 pid = bpf_get_current_pid_tgid();
        topic_info_hash.update(&pid, &t_info);
        bpf_probe_read_str(data.topic_name, 64, (const void *)t_info.topic_name);
        data.topic = t_info.tpoic_addr ;

        events.perf_submit(ctx, &data, sizeof(data));
    }
}

void r_DDS_Subscriber_create_datareader(struct pt_regs *ctx) { // 2:topic; ret: writer

    struct data_t data = {};
    pid_comm_ts(&data);
    data.fun_ID = 4;
    data.fun_ret = 1;
    u64 writer = PT_REGS_RC(ctx);
    data.writer = writer;
    topic_info* t_info_p;
    topic_info  t_info = {};
    u64 pid = bpf_get_current_pid_tgid();
    t_info_p = topic_info_hash.lookup(&pid);
    if (t_info_p) {
        t_info = *t_info_p;
        topic_info_hash.delete(&pid);
        topic_info_hash.update(&writer, &t_info);
        bpf_probe_read_str(data.topic_name, 64, (const void *)t_info.topic_name);
        data.topic = t_info.tpoic_addr ;

        events.perf_submit(ctx, &data, sizeof(data));

    }
}


void DDS_Publisher_create_datawriter(struct pt_regs *ctx) { // 2:topic; ret: writer

    struct data_t data = {};
    pid_comm_ts(&data);
    data.fun_ID = 2;
    data.fun_ret = 0;
    u64 topic = PT_REGS_PARM2(ctx);
    data.topic = topic;
    topic_info* t_info_p;
    topic_info  t_info = {};
    t_info_p = topic_info_hash.lookup(&topic);


    if (t_info_p) {
        t_info = *t_info_p;
        u64 pid = bpf_get_current_pid_tgid();
        topic_info_hash.update(&pid, &t_info);
        bpf_probe_read_str(data.topic_name, 64, (const void *)t_info.topic_name);
        data.topic = t_info.tpoic_addr ;

        events.perf_submit(ctx, &data, sizeof(data));
    }
}

void r_DDS_Publisher_create_datawriter(struct pt_regs *ctx) { // 2:topic; ret: writer

    struct data_t data = {};
    pid_comm_ts(&data);
    data.fun_ID = 2;
    data.fun_ret = 1;
    u64 writer = PT_REGS_RC(ctx);
    data.writer = writer;
    topic_info* t_info_p;
    topic_info  t_info = {};
    u64 pid = bpf_get_current_pid_tgid();
    t_info_p = topic_info_hash.lookup(&pid);
    if (t_info_p) {
        t_info = *t_info_p;
        topic_info_hash.delete(&pid);
        topic_info_hash.update(&writer, &t_info);
        bpf_probe_read_str(data.topic_name, 64, (const void *)t_info.topic_name);
        data.topic = t_info.tpoic_addr ;

        events.perf_submit(ctx, &data, sizeof(data));

    }
}

int DDS_ReaderCommon_samples_flush_copy(struct pt_regs *ctx) { // 1:data (v_message = data - 64)
    struct data_t data = {};
    pid_comm_ts(&data);
    data.fun_ID = 21;

    u64 pdata = PT_REGS_PARM1(ctx);
    u64 pv_mess = pdata - 64;
    v_message v_mess;
    bpf_probe_read(&v_mess, sizeof(v_message), (const void *)pv_mess);
    data.gid_sys = v_mess.writerGID.systemId;
    data.gid_local = v_mess.writerGID.localId;
    data.gid_seria = v_mess.writerGID.serial;
    data.seq = v_mess.sequenceNumber;
u64 pidip = data.pid;
    u64* reader;
    reader = read_topic_hash.lookup(&pidip);
    if (reader) {
    data.writer = *reader;
    u64 tmp = *reader;
    topic_info* t_info_p;
    topic_info  t_info = {};
        t_info_p =(topic_info* ) topic_info_hash.lookup(&tmp);
        if (t_info_p) {
            t_info = *t_info_p;
              bpf_probe_read_str(data.topic_name, 64, (const void *)t_info.topic_name);        
        }
     }
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;

}

void _DataReader_samples_flush_copy(struct pt_regs *ctx) {
    u64 reader = PT_REGS_PARM1(ctx);
if (0){
    struct data_t data = {};
    data.fun_ID = 99;
    topic_info* t_info_p;
    topic_info  t_info = {};
    t_info_p = topic_info_hash.lookup(&reader);
    if (t_info_p) {
        t_info = *t_info_p;
        bpf_probe_read_str(data.topic_name, 64, (const void *)t_info.topic_name);        
    }
    events.perf_submit(ctx, &data, sizeof(data));
}
    u64 pid = bpf_get_current_pid_tgid();
    read_topic_hash.update(&pid, &reader);
}

void r_DataReader_samples_flush_copy(struct pt_regs *ctx) {



    u64 pid = bpf_get_current_pid_tgid();
    read_topic_hash.delete(&pid);
}

int rtps_write(struct pt_regs *ctx){ // (xp, &sender, message)
    struct data_t data = {};
    pid_comm_ts(&data);
    data.fun_ID = 81;

    data.v_msg = PT_REGS_PARM3(ctx);
    v_message v_mess;
    bpf_probe_read(&v_mess, sizeof(v_message), (const void *)data.v_msg);
    data.seq = v_mess.sequenceNumber;
    data.gid_sys = v_mess.writerGID.systemId;
    data.gid_local = v_mess.writerGID.localId;
    data.gid_seria = v_mess.writerGID.serial;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int write_sample_kernel_seq_eot(struct pt_regs *ctx){ 
    struct data_t data = {};
    data.fun_ID = 82;
    pid_comm_ts(&data);

    data.s_d_data = PT_REGS_PARM4(ctx);
    data.seq = PT_REGS_PARM6(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int transmit_sample(struct pt_regs *ctx){
    struct data_t data = {};
    data.fun_ID = 83;
    pid_comm_ts(&data);

    data.xp = PT_REGS_PARM1(ctx); // struct nn_xpack *xp
    data.seq = PT_REGS_PARM3(ctx);
    data.s_d_data = PT_REGS_PARM5(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int create_fragment_message(struct pt_regs *ctx){
    struct data_t data = {};
    data.fun_ID = 84;
    pid_comm_ts(&data);

    data.seq = PT_REGS_PARM2(ctx);
    data.s_d_data = PT_REGS_PARM4(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int r_create_fragment_message(struct pt_regs *ctx){
    struct data_t data = {};
    data.fun_ID = 84;
    pid_comm_ts(&data);
    data.fun_ret = 1;

    data.fmsg = PT_REGS_RC(ctx); 

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int nn_xpack_addmsg(struct pt_regs *ctx){
    struct data_t data = {};
    data.fun_ID = 85;
    pid_comm_ts(&data);

    data.xp = PT_REGS_PARM1(ctx); // struct nn_xpack *xp
    data.fmsg = PT_REGS_PARM2(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int nn_xpack_send(struct pt_regs *ctx){
    struct data_t data = {};
    data.fun_ID = 86;
    pid_comm_ts(&data);

    data.xp = PT_REGS_PARM1(ctx); // struct nn_xpack *xp

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int nn_xpack_send1(struct pt_regs *ctx){ 
    struct data_t data = {};
    data.fun_ID = 87;
    pid_comm_ts(&data);

    data.xp = PT_REGS_PARM2(ctx); // struct nn_xpack *xp

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int ddsi_conn_write(struct pt_regs *ctx){
    struct data_t data = {};
    data.fun_ID = 88;
    pid_comm_ts(&data);

    data.s_d_data = PT_REGS_PARM1(ctx); // struct nn_xpack *xp
    data.seq = PT_REGS_PARM3(ctx);
    data.s_d_data = PT_REGS_PARM5(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


//u_dataReaderTake,v_dataReaderTake cmn_reader_action,
"""


# Function ID description
# var: funID
# 1 DDS_DomainParticipant_create_topic
# 2 DDS_Publisher_create_datawriter
# 3 writerWrite
# 4 DDS_Subscriber_create_datareader
# 5 DDS_DataReader_take

# 11 u_writerWrite
# 12 _DataWriterCopy
# 13 writerWrite

# 21
# 30
# 40
# 50
# 60
# 70
# 81 rtps_write
# 82 write_sample_kernel_seq_eot
# 83 transmit_sample
# 84 create_fragment_message
# 85 nn_xpack_addmsg
# 86 nn_xpack_send
# 87 nn_xpack_send1
# 88 ddsi_udp_conn_write
# 89 sendmsg (syscall)

##### Prober Variable Initialization
LIBPATH="/home/mxmsl2/yu-hong/workspace/opensplice/install/HDE/x86_64.linux-dev/lib/"

##### load BPF program
bpf = BPF(text=prog)

# Topic and Reader/ Writer Info
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_DomainParticipant_create_topic", fn_name="DDS_DomainParticipant_create_topic")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_DomainParticipant_create_topic", fn_name="r_DDS_DomainParticipant_create_topic")
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Publisher_create_datawriter", fn_name="DDS_Publisher_create_datawriter")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Publisher_create_datawriter", fn_name="r_DDS_Publisher_create_datawriter")

bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Subscriber_create_datareader", fn_name="DDS_Subscriber_create_datareader")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Subscriber_create_datareader", fn_name="r_DDS_Subscriber_create_datareader")


##### writerWrite / v_Message Info 
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym= "DDS_DataWriter_write", fn_name="DDS_DataWriter_write")
bpf.attach_uprobe(name="%slibddskernel.so"%LIBPATH, sym= "u_writerWrite", fn_name="u_writerWrite")
#bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="u_writeWithHandleAction", fn_name="u_writeWithHandleAction")
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="_DataWriterCopy", fn_name="_DataWriterCopy")
#bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="v_writerWrite", fn_name="v_writerWrite")
bpf.attach_uprobe(name="%slibddskernel.so"%LIBPATH, sym="writerWrite", fn_name="writerWrite")
#bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="v_networkQueueWrite", fn_name="enqueueSampleForResend")

##### ReaderRead / v_Message Info 
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_ReaderCommon_samples_flush_copy", fn_name="DDS_ReaderCommon_samples_flush_copy")

bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="_DataReader_samples_flush_copy", fn_name="_DataReader_samples_flush_copy")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="_DataReader_samples_flush_copy", fn_name="r_DataReader_samples_flush_copy")
# RTPS_WRITE / V_Message Info
bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="rtps_write", fn_name="rtps_write")
#bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="write_sample_kernel_seq_eot", fn_name="write_sample_kernel_seq_eot")
#bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="transmit_sample", fn_name="transmit_sample")
#bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="create_fragment_message", fn_name="create_fragment_message")

#bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="nn_xpack_addmsg", fn_name="nn_xpack_addmsg")
#bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="nn_xpack_send", fn_name="nn_xpack_send")
#bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="nn_xpack_send1", fn_name="nn_xpack_send1")
#bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="ddsi_udp_conn_write", fn_name="ddsi_udp_conn_write")


def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    found = re.search('gnome-shell', str(event.comm))
    found1 = re.search('gdbus', str(event.comm))
    found2 = re.search('NetworkManager', str(event.comm))
    found3 = re.search('systemd', str(event.comm))
    found4 = re.search('Xwayland', str(event.comm))
    if found or found1 or found2 or found3 or found4:
        pass
    elif 1:
        T="""
        print("%14d,%14d,\
 %4d,%20s,%20s,\
 %20s,%20s,%20s,\
 %20s,%20s,%20s,\
 %20s,%14d,%14d,%14d,%14d,\
 %14s,%8d,%20s" % 
         (event.ts, event.pid, 
          event.fun_ID, event.topic_name, hex(event.topic), 
          hex(event.writer), hex(event.dds_data), hex(event.writer_info), 
          hex(event.s_d_data), hex(event.fmsg), hex(event.xp), 
          hex(event.v_msg), event.gid_sys, event.gid_local, event.gid_seria, event.seq, 
          event.comm, event.sockfd, hex(event.msg)))

        print("%14d,%14d,\
 %20s,%14d,%14d,%14d,%14d,\
 %14s" % 
         (event.ts, event.pid, 
          hex(event.v_msg), event.gid_sys, event.gid_local, event.gid_seria, event.seq, 
          event.comm))  

"""
        print("%14d,%20s,%20s,%20d,\
%20d,%20d,\
%20d,%14d,%14d,\
%14d,%14d,%14d,%14d,%14d" % 
         (event.ts, str(event.comm, "utf-8"), str(event.topic_name, "utf-8"), event.pid,
          event.fun_ID, event.topic, 
          event.writer, event.dds_data, event.writer_info,  
          event.v_msg, event.gid_sys, event.gid_local, event.gid_seria, event.seq 
          ))  
    else:
        pass

Y="""
print("TIMESTAMP, PID,\
 FUN_ID, TOPIC_NAME, TOPIC_ADDR,\
 WRITER, DATA, WRITER_INFO,\
 SER_DATA, FMSG, XP,\
 V_MESSAGE, GID_SYS, GID_LOCAL, GID_SERIAL, SEQ_NUM,\
 COMM, SOCKFD, MSGHDR")
"""
bpf["events"].open_perf_buffer(print_event, page_cnt = 64*64)

while 1:
    bpf.perf_buffer_poll()


