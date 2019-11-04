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

def formatted_lines_to_trace(data_in, index_tab, name_info="empty"):
    from sofa_preprocess import trace_init
    result = []

    for line in data_in:
        trace = trace_init()
####### Create name information
        pkt_src = line[7] + ':' + str(line[8])
        pkt_dst = line[9] + ':' + str(line[10])
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

def ds_do_preprocess(cfg, logdir, pid):	
    from sofa_preprocess import sofa_fieldnames
    from sofa_preprocess import list_to_csv_and_traces
    
    ds_trace_field = ['timestamp', 'comm', 'pkt_type', 'tgid', 'tid', 'net_layer', 
                      'payload', 's_ip', 's_port', 'd_ip', 'd_port', 'checksum', 'start_time']

    tmp_ds_df = pd.read_csv('%s/ds_trace'%logdir, sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=False, header=0)
    tmp_ds_df = tmp_ds_df.dropna()
    ds_df = pd.DataFrame(columns=ds_trace_field)
    for i in range(len(tmp_ds_df.columns)):
        if i < 4:
            series = tmp_ds_df.iloc[:,i]
            ds_df.iloc[:,i] = series
        else:
            series = tmp_ds_df.iloc[:,i]
            ds_df.iloc[:,i+1] = series
            ds_df.iloc[:,i+1] = ds_df.iloc[:,i+1].astype('int64')

    ds_df['tid']  = ds_df['tgid'].apply( lambda x: x & 0xFFFFFFFF )

    ds_df['tgid'] = ds_df['tgid'].apply( lambda x: (x >> 32) & 0xFFFFFFFF )

    ds_df['s_ip'] = ds_df['s_ip'].apply( lambda x: str( x        & 0x000000FF) + "."
                                                 + str((x >>  8) & 0x000000FF) + "."
                                                 + str((x >> 16) & 0x000000FF) + "."
                                                 + str((x >> 24) & 0x000000FF) 
                                       )
    ds_df['d_ip'] = ds_df['d_ip'].apply( lambda x: str( x        & 0x000000FF) + "."
                                                 + str((x >>  8) & 0x000000FF) + "."
                                                 + str((x >> 16) & 0x000000FF) + "."
                                                 + str((x >> 24) & 0x000000FF) 
                                       )

    ds_df['s_port'] = ds_df.apply(lambda x: (ds_df['s_port'].values >> 8) & 0x00FF | (ds_df['s_port'].values << 8) & 0xFF00)

    ds_df['d_port'] = ds_df.apply(lambda x: (ds_df['d_port'].values >> 8) & 0x00FF | (ds_df['d_port'].values << 8) & 0xFF00)

### Normalize traces time
    ds_df.sort_values('timestamp')
    bpf_timebase_uptime = 0 
    bpf_timebase_unix = 0 
    with open(logdir + 'bpf_timebase.txt') as f:
        lines = f.readlines()
        bpf_timebase_unix = float(lines[-1].split(',')[0])
        bpf_timebase_uptime = float(lines[-1].split(',')[1].rstrip())
    offset = bpf_timebase_unix - bpf_timebase_uptime
    ds_df['timestamp'] = ds_df['timestamp'].apply(lambda x: (x / 10**9) + offset - cfg.time_base )

### Exclude data which is irrelevant to profiled program
    filter = ds_df['tgid'] == int(pid)
    ds_df = ds_df[filter]

    filter = ds_df['net_layer'] == 300
    ds_tx_df = ds_df[filter]

    filter = ds_df['net_layer'] == 1410
    ds_rx_df = ds_df[filter]

    ds_df.to_csv(logdir + 'ds_trace_%s'%pid, mode='w', index=False, float_format='%.9f')
    ds_tx_df.to_csv(logdir + 'ds_trace_pub_%s'%pid, mode='w', index=False, float_format='%.9f')
    ds_rx_df.to_csv(logdir + 'ds_trace_sub_%s'%pid, mode='w', index=False, float_format='%.9f')

    ds_norm_time_lists = [ds_tx_df.values.tolist(), ds_rx_df.values.tolist()]

    pid2ip = ds_tx_df[0:1].values.tolist()
    pid2ip = pid2ip[0]
    pid2ip = str(pid2ip[3]) + ' ' + str(pid2ip[7])
    f = open ('%spid2ip.txt'%logdir, 'w')
    f.write(pid2ip)
    f.close()

# DS trace 
# 0: Timestamp   # 3: tgid       # 6: payload     # 9: d_ip       # 12: start_time
# 1: comm        # 4: tid        # 7: s_ip        # 10: d_port
# 2: pkt_type    # 5: net_layer  # 8: s_port      # 11: Checksum 
 
# SOFA trace
# 0: timestamp   # 3: deviceId   # 6: bandwidth   # 9:  pid       # 12: category
# 1: event       # 4: copyKind   # 7: pkt_src     # 10: tid
# 2: duration    # 5: payload    # 8: pkt_dst     # 11: name
        
### Convert to SOFA trace format
    SOFA_trace_lists = []
    sofa_trace_index = [0, -1, -1, 11, -1, 6, -1, 1, 1, -1, 3, 1, -1]
    SOFA_trace_lists.append(formatted_lines_to_trace(ds_norm_time_lists[0], sofa_trace_index))
    SOFA_trace_lists.append(formatted_lines_to_trace(ds_norm_time_lists[1], sofa_trace_index))
    SOFA_trace_lists.append(trace_calculate_bandwidth(ds_norm_time_lists[0]))
    SOFA_trace_lists.append(trace_calculate_bandwidth(ds_norm_time_lists[1]))

### Convert to csv format which SOFA used to be stored as SOFA trace class  
    return [
            list_to_csv_and_traces(logdir, SOFA_trace_lists[0], 'ds_trace_tx%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[1], 'ds_trace_rx%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[2], 'ds_trace_tx_bandwidth%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[3], 'ds_trace_rx_bandwidth%s.csv'%pid, 'w')
           ]

def ds_find_sender(recv_iter, all_send_index_list, send_find, latency, negative,total_latency):

    recv_tmp = recv_iter[0]
    recv_feature_pattern = str(recv_tmp[7]) + str(recv_tmp[8]) + str(recv_tmp[9]) + str(recv_tmp[10]) + str(recv_tmp[11])
    #print(recv_feature_pattern)

    for send_cnt in range(len(all_send_index_list)):
        send_tmp = list(all_send_index_list[send_cnt][0])
        send_feature_pattern = str(send_tmp[7]) + str(send_tmp[8]) + str(send_tmp[9]) + str(send_tmp[10]) + str(send_tmp[11])
        #print(send_feature_pattern)
        if (recv_feature_pattern == send_feature_pattern):
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
    x = cnct_trace_tmp[0]
    y = pid_yPos_dic[str(cnct_trace_tmp[3])]

    if is_sender:
        name = str(cnct_trace_tmp[7]) + ':' + str(cnct_trace_tmp[8]) + ' | checksum = ' + str(cnct_trace_tmp[11])
    else:
        name = str(cnct_trace_tmp[9]) + ':' + str(cnct_trace_tmp[10]) + ' | checksum = ' + str(cnct_trace_tmp[11])

    trace = ds_cnct_trace_init()
    trace = [name, x, y]

    return trace
    
def ds_connect_preprocess(cfg):
    logdir = cfg.logdir
    ds_trace_field = ['timestamp', 'comm', 'pkt_type', 'tgid', 'tid', 'net_layer', 
                      'payload', 's_ip', 's_port', 'd_ip', 'd_port', 'checksum', 'start_time']
    all_send_socket = []
    all_recv_socket = []
    all_ds_df = pd.DataFrame([], columns=ds_trace_field)
    #a = highchart_annotation_label()
    #c = json.dumps(a.__dict__)
    pid_yPos_dic = {} 
    yPos_cnt = 0
    pid_ip_dic = {}

### Read in all nodes network activities information
    nodes_dir = glob.glob('[0-9]*')
    for nd_dir_iter in nodes_dir:

        f = open ('%s/pid2ip.txt'%nd_dir_iter)
        pid2ip = f.readline().split()
        f.close()

        pid_ip_dic[pid2ip[0]] = pid2ip[1]
        pid_yPos_dic[nd_dir_iter] = yPos_cnt

        ds_df = pd.read_csv('%s/ds_trace_%s'%(nd_dir_iter, nd_dir_iter), sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=True, header=0, float_precision='round_trip')
        all_ds_df = pd.concat([ds_df, all_ds_df], ignore_index=True, sort=False)

        yPos_cnt += 1
    y = [0,0,0,0,0,0,0,0,0,0,0,0,0]
    all_ds_df.sort_values(by='timestamp', inplace=True)
    ds_df_no_multicast = pd.DataFrame([], columns=ds_trace_field)
    ds_df_no_multicast = all_ds_df.apply( lambda x: x if (int(x['d_ip'].split('.')[0]) & 0xf0 != 0xe0) else None
                                         , result_type='broadcast', axis=1)
    ds_df_no_multicast = ds_df_no_multicast.dropna()
    
### Not really important, just nickname for sender and receiver records.
    print(ds_df_no_multicast)
    filter = ds_df_no_multicast['net_layer'] == 300 
    all_send_df = ds_df_no_multicast[filter]
    all_send_list = all_send_df.values.tolist()

    filter = ds_df_no_multicast['net_layer'] == 1410
    all_recv_df = ds_df_no_multicast[filter]
    all_recv_list = all_recv_df.values.tolist()

### Create list to accelerate preprocess when finding network connection which is accomplished by remove redundant calculation.
    all_send_index_list = []
    all_recv_index_list = []

    for index in range(len(all_send_list)):
        all_send_index_list.append([all_send_list[index], index])

    for index in range(len(all_recv_list)):
        all_recv_index_list.append([all_recv_list[index], index])

### Choose those data whose feature pattern is unique in the whole 
    send_canidate = [False] * len(all_send_list)
    feature_cnt_dic = {}
    for send_cnt in range(len(all_send_index_list)):
        send_tmp = all_send_index_list[send_cnt][0]
        send_feature_pattern = str(send_tmp[7]) + str(send_tmp[8]) + str(send_tmp[9]) + \
                               str(send_tmp[10]) + str(send_tmp[11])
        if send_feature_pattern not in feature_cnt_dic:
            feature_cnt_dic[send_feature_pattern] = 1
            send_canidate[send_cnt] = True
        else:
            feature_cnt_dic[send_feature_pattern] += 1
            send_canidate[send_cnt] = False

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
    pre_sent_count, pre_recv_count, positive_max, negative_max, total_latency = 0, 0, 0, 0, 0

    # Loop control paremeters
    latency, retry, negative = 1, True, False 
    while retry:
        retry = False

        for recv_cnt in range(recv_cnt_skip, len(all_recv_index_list)):
            total_latency, send_cnt = ds_find_sender(all_recv_index_list[recv_cnt], all_send_index_list, send_find, \
                                          latency, negative,total_latency)
### ------- Account ambibuous record (need to be filter out before making connection trace)
            if send_cnt:
                send_tmp = list(all_send_index_list[send_cnt][0])
                send_feature_pattern = str(send_tmp[7]) + str(send_tmp[8]) + str(send_tmp[9]) + \
                                       str(send_tmp[10]) + str(send_tmp[11])
                
                if send_feature_pattern not in feature_cnt_dic:
                    feature_cnt_dic[send_feature_pattern] = 1
                else:
                    feature_cnt_dic[send_feature_pattern] += 1

                send_select = all_send_index_list[send_cnt][1]
                recv_select = all_recv_index_list[recv_cnt][1]

### ----------- Find the max latency btween sender and receiver in the current searching range.
                if negative and (latency == 1):
                    abs_max = abs(all_send_index_list[send_cnt][0][0] - all_recv_index_list[recv_cnt][0][0])
                    if (abs_max > negative_max): 
                        negative_max = abs_max
                        #print(all_send_index_list[send_cnt][0])
                        #print(all_recv_index_list[recv_cnt][0])
                else:
                    if not negative and (latency == 1):
                        if (all_send_index_list[send_cnt][0][3] != all_recv_index_list[recv_cnt][0][3]):
                            abs_max = abs(all_send_index_list[send_cnt][0][0] - all_recv_index_list[recv_cnt][0][0])
                            if (abs_max > positive_max): 
                                positive_max = abs_max
                                #print(all_send_index_list[send_cnt][0])
                                #print(all_recv_index_list[recv_cnt][0])
                node2node = 'Node ' + str(all_send_index_list[send_cnt][0][7]) + \
                            ' to Node ' + str(all_recv_index_list[recv_cnt][0][9])
                
### -----------    If we want to create point to point connect effect in highchart's line chart, 
### ----------- we need to add null data in series for differentiating different connection.
                if node2node in node2node_traceIndex_dic:
                    cnct_trace = cnct_traces[node2node_traceIndex_dic[node2node]]
                    cnct_trace.append(create_cnct_trace(all_send_index_list[send_cnt][0], 1, pid_yPos_dic))
                    cnct_trace.append(create_cnct_trace(all_recv_index_list[recv_cnt][0], 0, pid_yPos_dic))
                    cnct_trace.append(ds_cnct_trace_init())
                    cnct_traces[node2node_traceIndex_dic[node2node]] = cnct_trace
                else:
                    node2node_traceIndex_dic[node2node] = trace_index
                    cnct_traces.append([])
                    cnct_trace = cnct_traces[trace_index]
                    cnct_trace.append(create_cnct_trace(all_send_index_list[send_cnt][0], 1, pid_yPos_dic))
                    cnct_trace.append(create_cnct_trace(all_recv_index_list[recv_cnt][0], 0, pid_yPos_dic))
                    cnct_trace.append(ds_cnct_trace_init())
                    cnct_traces[trace_index] = cnct_trace
                    trace_index += 1

                del all_send_index_list[send_cnt]
                del all_recv_index_list[recv_cnt]
                send_find[send_select] = True
                recv_find[recv_select] = True
                recv_cnt_skip = recv_cnt
                retry = True
                break
# --------- END if send_cnt:
# ----- END for recv_cnt in range(recv_cnt_skip, len(all_recv_index_list)):
# - END while retry:

### ---    Expand the searching range with larger latency if connection can not be figured out in previous given range. 
### --- Though in practice it should not exceed 1 second.
        if (not retry) and True:
            #print(len(all_send_index_list))
            #print(len(all_recv_index_list))
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
                #print("negative latency %d %d"%(latency,pre_sent_count - len(all_send_index_list)))
                #print(pre_recv_count - len(all_recv_index_list))
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

    #print(len(result_send_list))
    #print(len(result_recv_list))
    #print(positive_max)
    #print(negative_max)
    #print(float(total_latency))
    #print(cnct_trace)
    from sofa_preprocess import traces_to_json
    from sofa_models import SOFATrace
    # traces_to_json(traces, path, cfg, pid)
    traces = []
    ambiguous = 0
    for i in feature_cnt_dic:
        if feature_cnt_dic[i] > 1 :
            ambiguous += feature_cnt_dic[i] 

    y_categories = []
    for i in range(len(pid_yPos_dic)):
        y_categories.append([])
    for i in pid_yPos_dic:
        y_categories[pid_yPos_dic[i]] = pid_ip_dic[i]
    f = open('y_categories', 'w' )
    json.dump(y_categories, f)
    f.close()

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

