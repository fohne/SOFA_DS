import csv
import glob
import os
import re
import datetime
import itertools
import json
import numpy as np
import pandas as pd
import subprocess
import random 
from sofa_config import *

class highchart_annotation_label:
    def __init__(self):
        self.point = {'xAxis' : 0,'yAxis' : 0,'x' :0,'y':0}
        self.text = ''
   

def ds_cnct_trace_init():	
### field = name, x, y
    name, x, y  =  '', None, None
    trace = [name, x, y]
    return trace

def cor_tab_init():
    cor_tab = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]
    return cor_tab

def ds_trace_preprocess_functions_init():
    null_functions = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    return null_functions

def get_socket_src_addr(ds_trace):
    return ds_traces[13] + ':' + str(ds_traces[15])

def get_socket_des_addr(ds_trace):
    return ds_traces[14] + ':' + str(ds_traces[16])

def create_socket_info(ds_trace):
    return '[' + ds_traces[13] + ':' + str(ds_traces[15]) + " --> " +  ds_traces[14] + ':' + str(ds_traces[16]) + ']'

def ds_traces2sofa_traces(ds_traces, index_table, functions = ds_trace_preprocess_functions_init()):
    from sofa_preprocess import trace_init
    sofa_traces = []

    for ds_trace in ds_traces:
        sofa_trace = trace_init()

        for i in range(len(sofa_trace)):
            if index_table[i] != -1:
                sofa_trace[i] = ds_trace[index_table[i]]
            elif functions[i] != 0:
                sofa_trace[i] = functions[i](ds_trace)

        sofa_traces.append(sofa_trace)

    return sofa_traces

def formatted_lines_to_trace_v2(data_in, index_tab, name_info="empty"):
    from sofa_preprocess import trace_init
    result = []

    for line in data_in:
        trace = trace_init()
####### Create name information
        pkt_src = line[13] + ':' + str(line[15])
        pkt_dst = line[14] + ':' + str(line[16])
        name = '[' + pkt_src + " --> " + pkt_dst + ']'

        trace = [
                  line[index_tab[ 0]] if index_tab[ 0] != -1 else trace[ 0],
                  line[index_tab[ 1]] if index_tab[ 1] != -1 else trace[ 1],
                  line[index_tab[ 2]] if index_tab[ 2] != -1 else trace[ 2],
                  line[index_tab[ 3]] if index_tab[ 3] != -1 else trace[ 3],
                  line[index_tab[ 4]] if index_tab[ 4] != -1 else trace[ 4],
                  line[index_tab[ 5]] if index_tab[ 5] != -1 else trace[ 5],
                  line[index_tab[ 6]] if index_tab[ 6] != -1 else trace[ 6],
                  pkt_src             if index_tab[ 7] != -1 else trace[ 7], 
                  pkt_dst             if index_tab[ 8] != -1 else trace[ 8],
                  line[index_tab[ 9]] if index_tab[ 9] != -1 else trace[ 9],
                  line[index_tab[10]] if index_tab[10] != -1 else trace[10],
                  name                if index_tab[11] != -1 else name_info,
                  line[index_tab[12]] if index_tab[12] != -1 else trace[12]
                ]

        result.append(trace)
    return result

def dds_toSOFA_trace_v2(data_in, index_tab, name_info="empty"):
    from sofa_preprocess import trace_init
    result = []

    for line in data_in:
        trace = trace_init()
####### Create name information
        topic_name = line[7]
        gid = str(line[10])+'.'+str(line[11])+'.'+str(line[12])
        seq = line[9]
        name = '[' + topic_name + "]" + gid + ':' + str(seq)

        trace = [
                  line[index_tab[ 0]] if index_tab[ 0] != -1 else trace[ 0],
                  line[index_tab[ 1]] if index_tab[ 1] != -1 else trace[ 1],
                  line[index_tab[ 2]] if index_tab[ 2] != -1 else trace[ 2],
                  line[index_tab[ 3]] if index_tab[ 3] != -1 else trace[ 3],
                  line[index_tab[ 4]] if index_tab[ 4] != -1 else trace[ 4],
                  line[index_tab[ 5]] if index_tab[ 5] != -1 else trace[ 5],
                  line[index_tab[ 6]] if index_tab[ 6] != -1 else trace[ 6],
                  line[index_tab[ 7]] if index_tab[ 7] != -1 else trace[ 7], 
                  line[index_tab[ 8]] if index_tab[ 8] != -1 else trace[ 8],
                  line[index_tab[ 9]] if index_tab[ 9] != -1 else trace[ 9],
                  line[index_tab[10]] if index_tab[10] != -1 else trace[10],
                  name                if index_tab[11] != -1 else name_info,
                  line[index_tab[12]] if index_tab[12] != -1 else trace[12]
                ]

        result.append(trace)
    return result

def dds_toSOFA_trace(data_in, index_tab, name_info="empty"):
    from sofa_preprocess import trace_init
    result = []

    for line in data_in:
        trace = trace_init()
####### Create name information
        topic_name = line[2]
        gid = str(line[11])+'.'+str(line[12])+'.'+str(line[13])
        seq = line[14]
        name = '[' + topic_name + "]" + gid + ':' + str(seq)

        trace = [
                  line[index_tab[ 0]] if index_tab[ 0] != -1 else trace[ 0],
                  line[index_tab[ 1]] if index_tab[ 1] != -1 else trace[ 1],
                  line[index_tab[ 2]] if index_tab[ 2] != -1 else trace[ 2],
                  line[index_tab[ 3]] if index_tab[ 3] != -1 else trace[ 3],
                  line[index_tab[ 4]] if index_tab[ 4] != -1 else trace[ 4],
                  line[index_tab[ 5]] if index_tab[ 5] != -1 else trace[ 5],
                  line[index_tab[ 6]] if index_tab[ 6] != -1 else trace[ 6],
                  line[index_tab[ 7]] if index_tab[ 7] != -1 else trace[ 7], 
                  line[index_tab[ 8]] if index_tab[ 8] != -1 else trace[ 8],
                  line[index_tab[ 9]] if index_tab[ 9] != -1 else trace[ 9],
                  line[index_tab[10]] if index_tab[10] != -1 else trace[10],
                  name                if index_tab[11] != -1 else name_info,
                  line[index_tab[12]] if index_tab[12] != -1 else trace[12]
                ]

        result.append(trace)
    return result

def trace_calculate_bandwidth(data_in):
    from sofa_preprocess import trace_init
    result = list()
    total_payload = 0
    first_ts = 0
    curr_ts = 0
    i = 1 
    
    for line in data_in:
        trace = trace_init()

        curr_ts = line[0]
        if not first_ts:
            first_ts = line[0]
            curr_ts = line[0] * 2
        
        total_payload += line[6]
        trace[6] = total_payload / (curr_ts - first_ts)        
        trace[0] = line[0]
        result.append(trace)

    return result

def trace_calculate_bandwidth_v2(data_in):
    from sofa_preprocess import trace_init
    result = list()
    total_payload = 0
    first_ts = 0
    curr_ts = 0
    i = 1 
    
    for line in data_in:
        trace = trace_init()

        curr_ts = line[1]
        if not first_ts:
            first_ts = line[1]
            curr_ts = line[1] * 2
        
        total_payload += line[17]
        trace[6] = total_payload / (curr_ts - first_ts)        
        trace[0] = line[1]
        result.append(trace)

    return result

def ds_dds_preprocess(cfg, logdir, pid):	
    from sofa_preprocess import sofa_fieldnames
    from sofa_preprocess import list_to_csv_and_traces

    trace_field = ['timestamp', 'start_ts', 'end_ts', 'record_type', 'tgid', 'tid', 'fun_ID', 'topic_name', 'comm', 'seq', 
                   'gid_sys', 'gid_local', 'gid_seria', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5', 'arg6', 'link', 'ret']
    ds_df = pd.DataFrame(columns=trace_field)

    tmp_df = pd.read_csv('%s/ds_dds_trace'%logdir, sep=',\s+', delimiter=',', encoding="utf-8", skipinitialspace=False, header=0)
    tmp_df = tmp_df.dropna()

    for i in range(len(tmp_df.columns)):
        if i < 5:
            series = tmp_df.iloc[:,i]

            ds_df.iloc[:,i] = series
            ds_df.iloc[:,i] = ds_df.iloc[:,i].astype('int64')
        else:
            series = tmp_df.iloc[:,i]
            ds_df.iloc[:,i+1] = series
            if i != 6 and i != 7:
                ds_df.iloc[:,i+1] = ds_df.iloc[:,i+1].astype('int64')

    ds_df['tid']  = ds_df['tgid'].astype('int64').apply( lambda x: x & 0xFFFFFFFF )
    ds_df['tgid'] = ds_df['tgid'].apply( lambda x: (int(x) >> 32) & 0xFFFFFFFF )

    filter = ds_df['tgid'] == int(pid)
    ds_df  = ds_df[filter]
    ds_df.to_csv(logdir + 'ds_trace_%s'%pid, mode='w', index=False, float_format='%.9f')


### Normalize SOFA traces timeline
    ds_df.sort_values('start_ts')
    bpf_timebase_uptime = 0 
    bpf_timebase_unix = 0 
    
    with open(logdir + 'bpf_timebase.txt') as f:
        lines = f.readlines()
        bpf_timebase_unix = float(lines[-1].split(',')[0])
        bpf_timebase_uptime = float(lines[-1].split(',')[1].rstrip())
    offset = bpf_timebase_unix - bpf_timebase_uptime
    ds_df['start_ts'] = ds_df['start_ts'].apply(lambda x: (x / 10**9) + offset - cfg.time_base )
    ds_df[  'end_ts'] = ds_df[  'end_ts'].apply(lambda x: (x / 10**9) + offset - cfg.time_base )

### Preprocess socket trace data
  # socket trace field name meaning
  # arg1: source IP               # arg2: destination IP
  # arg3: source port             # arg4: destination port
  # arg5: payload size            # arg6: checksum

    socket_df  = pd.DataFrame(columns=trace_field)
    filter     = ds_df['record_type'] == 2 # 2 for socket traces
    socket_df  = ds_df[filter]
    
    socket_df['arg1'] = socket_df['arg1'].apply(lambda x: str( x        & 0x000000FF) + "."
                                                        + str((x >>  8) & 0x000000FF) + "."
                                                        + str((x >> 16) & 0x000000FF) + "."
                                                        + str((x >> 24) & 0x000000FF) 
                                               )
    socket_df['arg2'] = socket_df['arg2'].apply(lambda x: str( x        & 0x000000FF) + "."
                                                        + str((x >>  8) & 0x000000FF) + "."
                                                        + str((x >> 16) & 0x000000FF) + "."
                                                        + str((x >> 24) & 0x000000FF) 
                                               )
#   socket_df['arg3'] = socket_df.apply(lambda x: (socket_df['arg3'].values >> 8) & 0x00FF | (socket_df['arg3'].values << 8) & 0xFF00)
    socket_df['arg3'] = socket_df['arg3'].apply(lambda x: (x >> 8) & 0x00FF | (x << 8) & 0xFF00)
    socket_df['arg4'] = socket_df['arg4'].apply(lambda x: (x >> 8) & 0x00FF | (x << 8) & 0xFF00)

### Classify socket traces by function ID 
  # 20: socket_sendmsg
  # 30: socket_recvmsg
    filter       = socket_df['fun_ID'] == 20
    socket_tx_df = socket_df[filter]

    filter       = socket_df['fun_ID'] == 30
    socket_rx_df = socket_df[filter]

    socket_df.to_csv(logdir + 'socket_trace_%s'%pid, mode='w', index=False, float_format='%.9f')
    socket_tx_df.to_csv(logdir + 'socket_trace_tx_%s'%pid, mode='w', index=False, float_format='%.9f')
    socket_rx_df.to_csv(logdir + 'socket_trace_rx_%s'%pid, mode='w', index=False, float_format='%.9f')

    socket_norm_time_lists = [socket_tx_df.values.tolist(), socket_rx_df.values.tolist()]

### pid to IP/Port mapping
    pid2ip = socket_tx_df[0:1].values.tolist()
    pid2ip = pid2ip[0]
    pid2ip = str(pid2ip[4]) + ' ' + str(pid2ip[13]) + ":" + str(pid2ip[15])
    f = open ('%spid2ip.txt'%logdir, 'w')
    f.write(pid2ip)
    f.close()

# DS/DDS trace field index/name
# 0: Timestamp       # 3: record_type       # 6: fun_ID            # 9: seq          # 12: gid_seria         # 20: ret
# 1: start_TS        # 4: tgid              # 7: topic_name        # 10: gid_sys     # 13 ~ 18: arg1 ~ arg6 
# 2: end_TS          # 5: tid               # 8: comm              # 11: gid_local   # 19: link       
  
# SOFA trace field index/name
# 0: timestamp   # 3: deviceId   # 6: bandwidth   # 9:  pid       # 12: category
# 1: event       # 4: copyKind   # 7: pkt_src     # 10: tid
# 2: duration    # 5: payload    # 8: pkt_dst     # 11: name
        
### Convert DS teace to SOFA trace format
    SOFA_trace_lists = []
    ds_trace4sofa_trace_index = [1, -1, -1, 18, -1, 17, -1, 
                        1,  1, -1,  4,  1, -1]

    functions = ds_trace_preprocess_functions_init()
    functions[7] = get_socket_src_addr
    functions[8] = get_socket_des_addr
    functions[11] = create_socket_info

    SOFA_trace_lists.append(ds_traces2sofa_traces(socket_norm_time_lists[0], ds_trace4sofa_trace_index, functions))
    SOFA_trace_lists.append(ds_traces2sofa_traces(socket_norm_time_lists[1], ds_trace4sofa_trace_index, functions))
    SOFA_trace_lists.append(trace_calculate_bandwidth_v2(socket_norm_time_lists[0]))
    SOFA_trace_lists.append(trace_calculate_bandwidth_v2(socket_norm_time_lists[1]))

### Preprocess DDS trace
    dds_df = pd.DataFrame(columns=trace_field)
    filter = ds_df['record_type'] == 1 # 1 for DDS traces
    dds_df = ds_df[filter]

    filter = dds_df['fun_ID'] <= 1
    dds_pub_df = dds_df[filter]

    filter = dds_df['fun_ID'] == 7
    dds_sub_df = dds_df[filter]

    dds_df.to_csv(logdir + 'dds_trace_%s'%pid, mode='w', index=False, float_format='%.9f')
    dds_pub_df.to_csv(logdir + 'dds_trace_pub_%s'%pid, mode='w', index=False, float_format='%.9f')
    dds_sub_df.to_csv(logdir + 'dds_trace_sub_%s'%pid, mode='w', index=False, float_format='%.9f')

    dds_norm_time_lists = [dds_pub_df.values.tolist(), dds_sub_df.values.tolist()]


# DS/DDS trace 
# 0: Timestamp       # 3: record_type       # 6: fun_ID            # 9: seq          # 12: gid_seria         # 20: ret
# 1: start_TS        # 4: tgid              # 7: topic_name        # 10: gid_sys     # 13 ~ 18: arg1 ~ arg6 
# 2: end_TS          # 5: tid               # 8: comm              # 11: gid_local   # 19: link    

# SOFA trace
# 0: timestamp   # 3: deviceId   # 6: bandwidth   # 9:  pid       # 12: category
# 1: event       # 4: copyKind   # 7: pkt_src     # 10: tid
# 2: duration    # 5: payload    # 8: pkt_dst     # 11: name

    sofa_trace_index = [1,  6, -1, -1, -1, -1, -1,  
                       -1, -1,  4,  5,  8, -1]
    SOFA_trace_lists.append(dds_toSOFA_trace_v2(dds_norm_time_lists[0], sofa_trace_index))
    SOFA_trace_lists.append(dds_toSOFA_trace_v2(dds_norm_time_lists[1], sofa_trace_index))

### Convert to csv format which SOFA used to be stored as SOFA trace class  
    return [
            list_to_csv_and_traces(logdir, SOFA_trace_lists[0], 'ds_trace_tx%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[1], 'ds_trace_rx%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[2], 'ds_trace_tx_bandwidth%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[3], 'ds_trace_rx_bandwidth%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[4], 'dds_trace_pub%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[5], 'dds_trace_sub%s.csv'%pid, 'w')
           ]


def create_span_in_hightchart (x, y, name):
    trace = ds_cnct_trace_init()
    trace = [name, x, y]
    return trace

# DS/DDS trace 
# 0: Timestamp       # 3: record_type       # 6: fun_ID            # 9: seq          # 12: gid_seria         # 20: ret
# 1: start_TS        # 4: tgid              # 7: topic_name        # 10: gid_sys     # 13 ~ 18: arg1 ~ arg6 
# 2: end_TS          # 5: tid               # 8: comm              # 11: gid_local   # 19: link  
def ds_dds_create_span(cfg):
    trace_field = ['timestamp', 'start_ts', 'end_ts', 'record_type', 'tgid', 'tid', 'fun_ID', 'topic_name', 'comm', 'seq', 
                   'gid_sys', 'gid_local', 'gid_seria', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5', 'arg6', 'link', 'ret']
    all_df = pd.DataFrame([], columns=trace_field)

    nodes_dir = glob.glob('[0-9]*')
    pid_map = {}
    vid_seq_map = {}

    for nd_dir_iter in nodes_dir:

        df = pd.read_csv('%s/ds_dds_trace_%s'%(nd_dir_iter, nd_dir_iter), sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=True, header=0, float_precision='round_trip')

        all_df = pd.concat([df, all_df], ignore_index=True, sort=False)

    for row in range(all_df.size):
        print(all_df[row][10])
        vid_seq = str(all_df[row][10]) + str(all_df[row][11]) + str(all_df[row][12]) + str(all_df[row][9])

        if uid not in vid_seq_map:
            vid_seq_map[str(vid_seq)] = []
            vid_seq_map[str(vid_seq)].append(all_df[row])
        else:
            vid_seq_map[str(vid_seq)].append(all_df[row])

    df_in_process = pd.DataFrame([], columns=trace_field)                            
    for vid_seq in vid_seq_map:
        tmp_df = pd.DataFrame(vid_seq_map[vid_seq], columns=trace_field)
        filter = tmp_df['fun_ID'] == 1
        start_df = tmp_df[filter]
        start = start_df[0]['start_ts']
        tmp_df['timestamp'] = tmp_df['start_ts']
        tmp_df[ 'start_ts'] = tmp_df['start_ts'].apply(lambda x: x - start)
        tmp_df[   'end_ts'] = tmp_df[  'end_ts'].apply(lambda x: x - start)
        df_in_process = pd.concat([tmp_df, df_in_process], ignore_index=True, sort=False)
        
    table4SOFA = []
    for row in range(len(df_in_process)):
        tmp_df = df_in_process[row]
        x = tmp_df['timestamp']
        y1 = tmp_df['start_ts']
        y2 = tmp_df['end_ts']
        y1_info = 'functionID: ' + str(tmp_df['Fun_ID']) + ' Start time:' + str(tmp_df['timestamp'])
        y2_info = 'functionID: ' + str(tmp_df['Fun_ID']) + ' End time:' + str(tmp_df['timestamp'] + tmp_df['end_ts'])
        table4SOFA.append([x,y1,y1_info])
        table4SOFA.append([x,y2,y2_info])

    field4sofa = ['x', 'y', 'info']
    df4sofa = pd.DataFrame(table4SOFA, columns=field4sofa)
    df4sofa.sort_values('x')

    cnct_trace = []
    for row in range(len(df4sofa)):
        if row%2 == 0:
            cnct_trace.append(create_span_in_hightchart(df4sofa[row]['x'], df4sofa[row]['y'], df4sofa[row]['info']))

        else:
            cnct_trace.append(create_span_in_hightchart(df4sofa[row]['x'], df4sofa[row]['y'], df4sofa[row]['info']))
            cnct_trace.append(ds_cnct_trace_init())
                    
        
    cnct_trace = pd.DataFrame(cnct_trace, columns = ['name','x','y'])

    sofatrace = SOFATrace()
    sofatrace.name = 'DDS_span_view' 
    sofatrace.title = 'DDS_Span'
    sofatrace.color = 'rgba(%s,%s,%s,0.8)' %(random.randint(0,255),random.randint(0,255),random.randint(0,255))
    sofatrace.x_field = 'x'
    sofatrace.y_field = 'y'
    sofatrace.data = cnct_trace
    traces.append(sofatrace)

    traces_to_json(traces, 'span_view.js', cfg, '')      


# Not used
def ds_find_sender(recv_iter, all_send_index_list, send_find, send_canidate, latency, negative,total_latency):

    recv_tmp = recv_iter[0]
    recv_feature_pattern = str(recv_tmp[7]) + str(recv_tmp[8]) + str(recv_tmp[9]) + str(recv_tmp[10]) + str(recv_tmp[11])
    #print(recv_feature_pattern)

    for send_cnt in range(len(all_send_index_list)):
        send_tmp = list(all_send_index_list[send_cnt][0])
        send_feature_pattern = str(send_tmp[7]) + str(send_tmp[8]) + str(send_tmp[9]) + str(send_tmp[10]) + str(send_tmp[11])
        #print(send_feature_pattern)
        if (recv_feature_pattern == send_feature_pattern) and send_canidate[send_cnt]:
            send_select = all_send_index_list[send_cnt][1]

            if not negative:
                if (0 < recv_tmp[0] - send_tmp[0] < latency):              
                    if not send_find[send_select]:
                        total_latency += recv_tmp[0] - send_tmp[0] 
                        return total_latency, send_cnt
            else:
                latency = 0 - latency
                if (latency < recv_tmp[0] - send_tmp[0] < 0):
                    if not send_find[send_select]:
                        total_latency += recv_tmp[0] - send_tmp[0]
                        return total_latency, send_cnt

    return total_latency, False

### Add single point information in Highchart's line chart data format 
def create_cnct_trace(cnct_list, is_sender, pid_yPos_dic):
    cnct_trace_tmp = list(cnct_list)
    
    name = ''
    x = cnct_trace_tmp[1]
    y = pid_yPos_dic[str(cnct_trace_tmp[4])]

    if is_sender:
        name = str(cnct_trace_tmp[13]) + ':' + str(cnct_trace_tmp[15]) + ' | checksum = ' + str(cnct_trace_tmp[18])
    else:
        name = str(cnct_trace_tmp[14]) + ':' + str(cnct_trace_tmp[16]) + ' | checksum = ' + str(cnct_trace_tmp[18])

    trace = ds_cnct_trace_init()
    trace = [name, x, y]

    return trace
    
def ds_connect_preprocess(cfg):
# DS/DDS trace field name
# 0: Timestamp       # 3: record_type       # 6: fun_ID            # 9: seq          # 12: gid_seria         # 20: ret
# 1: start_TS        # 4: tgid              # 7: topic_name        # 10: gid_sys     # 13 ~ 18: arg1 ~ arg6 
# 2: end_TS          # 5: tid               # 8: comm              # 11: gid_local   # 19: link   
    logdir = cfg.logdir
    ds_trace_field = ['timestamp', 'start_ts', 'end_ts', 'record_type', 'tgid', 'tid', 'fun_ID', 'topic_name', 'comm', 'seq', 
                   'gid_sys', 'gid_local', 'gid_seria', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5', 'arg6', 'link', 'ret']

    all_ds_df = pd.DataFrame([], columns=ds_trace_field)
   
    pid_yPos_dic = {} 
    yPos_cnt = 0
    pid_ip_dic = {}
    
    adjust_list = []
    en_adjust = 1
    second_1 = 1
    adjust_file_exist = 0
    if (os.path.exists('adjust_offset.txt')):
        adjust_file_exist = 1
        f = open('adjust_offset.txt')
        adjust_list = f.readline().split(',')
        second_1 = float(adjust_list[2])

### Read in all nodes network activities information
    nodes_dir = glob.glob('[0-9]*')
    command_dic = {}
    for nd_dir_iter in nodes_dir:

        f = open ('%s/pid2ip.txt'%nd_dir_iter)
        pid2ip = f.readline().split()
        f.close()
        f = open ('%s/command.txt'%nd_dir_iter)
        command = f.readline().split()
        f.close()
        command_dic[command[0]] = 1
        pid_ip_dic[pid2ip[0]] = pid2ip[1]
        pid_yPos_dic[nd_dir_iter] = yPos_cnt

        ds_df = pd.read_csv('%s/socket_trace_%s'%(nd_dir_iter, nd_dir_iter), sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=True, header=0, float_precision='round_trip')

            
        if en_adjust and adjust_file_exist and (nd_dir_iter == adjust_list[0]):
            ds_df['start_ts'] = ds_df['start_ts'].apply( lambda x: x - float(adjust_list[1]) )


        all_ds_df = pd.concat([ds_df, all_ds_df], ignore_index=True, sort=False)

        yPos_cnt += 1

    all_ds_df.sort_values(by='start_ts', inplace=True)
    all_ds_df.to_csv('processed_ds_record', mode='w', index=False, float_format='%.9f')
    print('\nIn kernel ds data preprocess done')



    y = [0,0,0,0,0,0,0,0,0,0,0,0,0]

    ds_df_no_multicast = pd.DataFrame([], columns=ds_trace_field)
    ds_df_no_multicast = all_ds_df.apply( lambda x: x if (int(x['arg2'].split('.')[0]) & 0xf0 != 0xe0) else 0
                                         , result_type='broadcast', axis=1)
    #print(ds_df_no_multicast)
    #ds_df_no_multicast = ds_df_no_multicast.dropna()
    #ds_df_no_multicast = all_ds_df

### Not really important, just nickname for sender and receiver records.
    filter = ds_df_no_multicast['fun_ID'] == 20 
    all_send_df = ds_df_no_multicast[filter]
    #all_send_df = all_send_df.apply(lambda x: x if (x['comm'].find('xmit.user')>-1) else None, result_type='broadcast', axis=1)
    all_send_df = all_send_df.dropna()	
    all_send_list = all_send_df.values.tolist()

    filter = ds_df_no_multicast['fun_ID'] == 30
    all_recv_df = ds_df_no_multicast[filter]
    all_recv_list = all_recv_df.values.tolist()

    print(all_recv_df)
### Create list to accelerate preprocess when finding network connection which is accomplished by remove redundant calculation.
    all_send_index_list = []
    all_recv_index_list = []

    for index in range(len(all_send_list)):
        all_send_index_list.append([all_send_list[index], index])

    for index in range(len(all_recv_list)):
        all_recv_index_list.append([all_recv_list[index], index])

### Choose those data whose feature pattern is unique in the whole 
    send_canidate = [False] * len(all_send_list)
    feature_send_dic = {}
    for send_cnt in range(len(all_send_index_list)):
        send_tmp = all_send_index_list[send_cnt][0]
        send_feature_pattern = \
                               str(send_tmp[13]) + str(send_tmp[15]) + str(send_tmp[14]) + \
                               str(send_tmp[16]) + str(send_tmp[18])
        if send_feature_pattern not in feature_send_dic:
            feature_send_dic[send_feature_pattern] = [1, send_cnt]
            send_canidate[send_cnt] = True
        else:
            feature_send_dic[send_feature_pattern][0] += 1
   #         send_canidate[feature_send_dic[send_feature_pattern][1]] = False
            send_canidate[send_cnt] = True
                             
    recv_canidate = [False] * len(all_recv_list)
    feature_recv_dic = {}
    for recv_cnt in range(len(all_recv_index_list)):
        recv_tmp = all_recv_index_list[recv_cnt][0]
        recv_feature_pattern =  \
                               str(recv_tmp[13]) + str(recv_tmp[15]) + str(recv_tmp[14]) + \
                               str(recv_tmp[16]) + str(recv_tmp[18])
        if recv_feature_pattern not in feature_recv_dic:
            feature_recv_dic[recv_feature_pattern] = [1, recv_cnt]
            recv_canidate[recv_cnt] = True
        else:
            feature_recv_dic[recv_feature_pattern][0] += 1
#            recv_canidate[feature_recv_dic[recv_feature_pattern][1]] = False
            recv_canidate[recv_cnt] = True

### Create connection view by add highchart line data
    # Used to avoid miss selection of same data if there exist multiple same feature pattern in the data.
    send_find = [False] * len(all_send_list)
    recv_find = [False] * len(all_recv_list)

    # Create node to node connection view traces
    cnct_trace = []
    cnct_traces =[]
    trace_index = 0
    node2node_traceIndex_dic = {}

    # Because searching list is ordered and none matched received data should not 
    # search again (not found in previous searing), skip previous searched data.
    recv_cnt_skip = 0 

    # Accounting
    pre_sent_count, pre_recv_count, positive_min, negative_max, total_latency = 0, 0, 16, 0, 0
    who = 0
    match_cnt, neg_count, pos_count, total_neg, total_pos= 0, 0, 0, 0, 0

    # Loop control paremeters
    latency, retry, negative = 1, True, False 
    neg_who_dic = {} # []
    accounting = {}
    while retry:
        retry = False

        for recv_cnt in range(len(all_recv_index_list)):
            if not recv_canidate[all_recv_index_list[recv_cnt][1]]:
            #if  recv_find[all_recv_index_list[recv_cnt][1]]:
                continue

            recv_tmp = all_recv_index_list[recv_cnt][0]
            recv_feature_pattern = \
                                   str(recv_tmp[13]) + str(recv_tmp[15]) + str(recv_tmp[14]) + \
                                   str(recv_tmp[16]) + str(recv_tmp[18])
            print(recv_feature_pattern)
            sfind = False
            for send_cnt in range(len(all_send_index_list)):
                if not send_canidate[all_send_index_list[send_cnt][1]]:
                #if  send_find[all_send_index_list[send_cnt][1]]:
                    continue

                send_tmp = list(all_send_index_list[send_cnt][0])
                if  recv_tmp[0] - send_tmp[0] < 0:
                    pass #break
                send_feature_pattern =  \
                                       str(send_tmp[13]) + str(send_tmp[15]) + str(send_tmp[14]) + \
                                       str(send_tmp[16]) + str(send_tmp[18])

                if (recv_feature_pattern == send_feature_pattern):
                    sfind = send_cnt
                    match_cnt += 1

                    acc_id = str(send_tmp[13]) + " to " + str(send_tmp[14])
                    if acc_id not in accounting:
                        accounting[acc_id] = {}
                        accounting[acc_id]['latency'] = []
                        accounting[acc_id]['bandwidth'] = []

                    accounting[acc_id]['latency'].append(recv_tmp[1] - send_tmp[1])
                    accounting[acc_id]['bandwidth'].append([send_tmp[1], recv_tmp[1], recv_tmp[17] ])

                    if  recv_tmp[1] - send_tmp[1] < 0:
                        continue
                        neg_count += 1
                        total_neg += recv_tmp[1] - send_tmp[1]
                        if send_tmp[4] in neg_who_dic:
                            neg_who_dic[send_tmp[4]]['neg_count'] += 1
                        else:
                            neg_who_dic[send_tmp[4]] = {}
                            neg_who_dic[send_tmp[4]]['neg_count'] = 1
                            neg_who_dic[send_tmp[4]]['neg_max'] = 0
                            neg_who_dic[send_tmp[4]]['pos_count'] = 0
                            neg_who_dic[send_tmp[4]]['pos_min'] = 16

                        print(abs(recv_tmp[1] - send_tmp[1]))
                        if 6 > abs(recv_tmp[1] - send_tmp[1]) > neg_who_dic[send_tmp[4]]['neg_max']: 
                            negative_max = abs(recv_tmp[1] - send_tmp[1])
                            neg_who_dic[send_tmp[4]]['neg_max'] = negative_max
                            
                    else:
                        pos_count += 1
                        total_pos += recv_tmp[1] - send_tmp[1]

                        if send_tmp[4] in neg_who_dic:
                            neg_who_dic[send_tmp[4]]['pos_count'] += 1
                        else:
                            neg_who_dic[send_tmp[4]] = {}
                            neg_who_dic[send_tmp[4]]['neg_count'] = 0
                            neg_who_dic[send_tmp[4]]['neg_max'] = 0
                            neg_who_dic[send_tmp[4]]['pos_count'] = 1
                            neg_who_dic[send_tmp[4]]['pos_min'] = 16

                        #if positive_min > abs(recv_tmp[0] - send_tmp[0]) and who !=send_tmp[3]:
                        if abs(recv_tmp[1] - send_tmp[1]) < neg_who_dic[send_tmp[4]]['pos_min']: 
                            positive_min = abs(recv_tmp[1] - send_tmp[1])
                            neg_who_dic[send_tmp[4]]['pos_min'] = positive_min
                    break;
           # total_latency, send_cnt = \
           # ds_find_sender(all_recv_index_list[recv_cnt], all_send_index_list, send_find, send_canidate, latency, negative,total_latency)


### ------- Account ambibuous record (need to be filter out before making connection trace)
            if sfind:

                send_select = all_send_index_list[sfind][1]
                recv_select = all_recv_index_list[recv_cnt][1]

                node2node = 'Node ' + str(all_send_index_list[sfind][0][13]) + \
                            ' to Node ' + str(all_recv_index_list[recv_cnt][0][14])
                print(node2node)
### -----------    If we want to create point to point connect effect in highchart's line chart, 
### ----------- we need to add null data in series for differentiating different connection.
                if node2node in node2node_traceIndex_dic:
                    cnct_trace = cnct_traces[node2node_traceIndex_dic[node2node]]
                    cnct_trace.append(create_cnct_trace(all_send_index_list[sfind][0], 1, pid_yPos_dic))
                    cnct_trace.append(create_cnct_trace(all_recv_index_list[recv_cnt][0], 0, pid_yPos_dic))
                    cnct_trace.append(ds_cnct_trace_init())
                    cnct_traces[node2node_traceIndex_dic[node2node]] = cnct_trace
                else:
                    node2node_traceIndex_dic[node2node] = trace_index
                    cnct_traces.append([])
                    cnct_trace = cnct_traces[trace_index]
                    cnct_trace.append(create_cnct_trace(all_send_index_list[sfind][0], 1, pid_yPos_dic))
                    cnct_trace.append(create_cnct_trace(all_recv_index_list[recv_cnt][0], 0, pid_yPos_dic))
                    cnct_trace.append(ds_cnct_trace_init())
                    cnct_traces[trace_index] = cnct_trace
                    trace_index += 1

                del all_send_index_list[sfind]
                send_find[send_select] = True
                recv_find[recv_select] = True
                #retry = True

# --------- END if sfind:
# ----- END for recv_cnt in range(recv_cnt_skip, len(all_recv_index_list)):
# - END while retry:

### ---    Expand the searching range with larger latency if connection can not be figured out in previous given range. 
### --- Though in practice it should not exceed 1 second.

        if ( retry) and True:

            if not negative:
                #print("positive latency %d %d"%(latency, len(all_send_index_list)))
                if (latency < 1):
                    retry = True
                    latency += 1
                    recv_cnt_skip = 0
                else:
                    pre_sent_count = len(all_send_index_list)
                    pre_recv_count = len(all_recv_index_list)
                    negative = True
                    retry = True
                    latency = 1
                    recv_cnt_skip = 0
            else:

                pre_sent_count = len(all_send_index_list)
                pre_recv_count = len(all_recv_index_list)
                if (latency < 2):
                    retry = True
                    latency += 1
                    recv_cnt_skip = 0

    result_send_list = []
    result_recv_list = []
    for i in range(len(all_send_index_list)):
        result_send_list.append(all_send_index_list[i][0])

    for i in range(len(all_recv_index_list)):
        result_recv_list.append(all_recv_index_list[i][0])



    neg_count_max = 0
    for neg_who in neg_who_dic:
        print(('%s count: %s')%(neg_who, neg_who_dic[neg_who]['neg_count']))
        if (neg_who_dic[neg_who]['neg_count'] > neg_count_max):
            who = neg_who
            neg_count_max = neg_who_dic[who]['neg_count']
    if who in neg_who_dic:
        negative_max = neg_who_dic[who]['neg_max']

    for neg_who in neg_who_dic:
        if (neg_who != who):
            positive_min = neg_who_dic[neg_who]['pos_min']

    recv_nfind = [not i for i in recv_find]
    send_nfind = [not i for i in send_find]
    #print(send_nfind)
    recv_not_find = all_recv_df[recv_nfind]
    send_not_find = all_send_df[send_nfind]
    all_not_df = pd.concat([send_not_find, recv_not_find], ignore_index=True, sort=False)
    os.system('pwd')
    all_not_df.sort_values(by='timestamp', inplace=True)
    all_not_df.to_csv('nfound', mode='w', index=False, float_format='%.9f')






#    print(recv_not_find)
    print('match count: %s'%match_cnt)
    print('min positive latency: %s'%positive_min)
    print('max negative latency: %s'%negative_max)
    print('neg count %s'% neg_count)
    print('neg total %s'%total_neg)

    print('pos count %s'% pos_count)
    print('pos total %s'%total_pos)
    total_latency = float(total_neg)+float(total_pos)

    if neg_count > 5:
        neg_ratio = 0
        if positive_min > negative_max:
            neg_ratio_latancy = (positive_min - negative_max) * (1 - (total_pos/pos_count)/(total_pos/pos_count - total_neg/neg_count))
        print('max negative latency: %s'%negative_max)
        print('who: %s'%who)
        f = open('adjust_offset.txt','w')
        #if positive_min < negative_max:
         #   negative_max = positive_min
        if adjust_file_exist:
            if (who == int(adjust_list[0])):

                negative_max = float(adjust_list[1]) - total_neg 

       #     else:
      #          second_1 = negative_max - 0.0005
       #         who = int(adjust_list[0])
       #         negative_max = float(adjust_list[1]) - negative_max
        f.write(str(who))
        f.write(',')
        #f.write(str(total_neg/neg_count))
        #if (positive_min - negative_max) > 0:
          #  negative_max += (positive_min - negative_max)/2
        f.write(str(negative_max+neg_ratio_latancy))
        print('neg_ratio_latancy: %s'%neg_ratio_latancy)
        f.write(',')
        f.write(str(second_1))
        f.write('\n')
        f.close()
          
    print('total latency:%s'%float(total_latency))

    #print(cnct_trace)
    from sofa_preprocess import traces_to_json
    from sofa_models import SOFATrace
    # traces_to_json(traces, path, cfg, pid)
    traces = []
    #ambiguous = 0
    #for i in feature_cnt_dic:
    #    if feature_cnt_dic[i] > 1 :
    #        ambiguous += feature_cnt_dic[i] 

    y_categories = []
    for i in range(len(pid_yPos_dic)):
        y_categories.append([])
    for i in pid_yPos_dic:
        y_categories[pid_yPos_dic[i]] = pid_ip_dic[i]
    f = open('y_categories', 'w')
    json.dump(y_categories, f)
    f.close()
    #print(accounting)
    #f = open('ds_report.txt', 'w')

    for acc_id in accounting:
        print('\n')
        print(acc_id)
        df = pd.DataFrame(accounting[acc_id]['latency'])
        print('latency')
        print('%%.25: %f'%(df.quantile(0.25)))
        print('%%.50: %f'%(df.quantile(0.5)))
        print('%%.75: %f'%(df.quantile(0.75)))
        print('%%.95: %f'%(df.quantile(0.95)))
        print('mean: %f'%(df.mean()))

        band = accounting[acc_id]['bandwidth']
        df = pd.DataFrame(accounting[acc_id]['bandwidth'],columns=['send','recv','payload'])
        df.sort_values('send')
        band = df.values.tolist()
        band_result = []
        payload = 0
        for i in range(len(band)):
            payload += band[i][2]
            band_result.append(payload/(band[i][1] - band[0][0]))
        d = """
        interval = 1000
        if int(len(band) / interval):
            for i in range(int(len(band)/interval)):
                stime = band[i*interval][0]
            #print(stime)
                payload = 0
                for j in range(interval):
                    payload += band[i*interval+j][2]
                etime = band[i*interval + interval-1][1]
            #print(etime) 
                band_result.append(payload/(etime-stime))
        else:
            payload = 0
            for i in range(len(band)):
                payload += band[i][2]
            band_result.append(payload/(band[-1][1]-band[1][0]))"""
        df = pd.DataFrame(band_result)
        print('\nbandwidth')
        print('%%.25: %f'%(df.quantile(0.25)))
        print('%%.50: %f'%(df.quantile(0.5)))
        print('%%.75: %f'%(df.quantile(0.75)))
        print('%%.95: %f'%(df.quantile(0.95)))
        print('mean: %f\n'%(df.mean()))
    print('recv not find %d'%recv_find.count(False))
    print('send not find %d'%send_find.count(False))

    print('recv not canidate %d'%recv_canidate.count(False))
    print('send not canidate %d'%send_canidate.count(False))
    #for i in range(len(all_recv_list)):
     #   if not recv_find[i] and not recv_canidate[i]:
      #      print(all_recv_list[i])

    print('\n\n')
    for node2node in node2node_traceIndex_dic:

        cnct_trace = cnct_traces[node2node_traceIndex_dic[node2node]]
        cnct_trace = pd.DataFrame(cnct_trace, columns = ['name','x','y'])

        sofatrace = SOFATrace()
        sofatrace.name = 'ds_connection_trace%d' % node2node_traceIndex_dic[node2node]
        sofatrace.title = '%s' % node2node
        sofatrace.color = 'rgba(%s,%s,%s,0.8)' %(random.randint(0,255),random.randint(0,255),random.randint(0,255))
        sofatrace.x_field = 'x'
        sofatrace.y_field = 'y'
        sofatrace.data = cnct_trace
        traces.append(sofatrace)

    traces_to_json(traces, 'connect_view_data.js', cfg, '_connect')      
    return pid_yPos_dic

