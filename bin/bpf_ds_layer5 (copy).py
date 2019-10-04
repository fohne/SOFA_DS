#!/usr/bin/python

bpf_layer5_txt = """

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
