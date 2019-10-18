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



def ds_cnct_trace_init():	
#field = name, x, y
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
        # Create name information
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

    subprocess.call(['echo "timestamp, comm, pkt_type, tgid, tid, net_layer, payload, s_ip,\
                      s_port, d_ip, d_port, checksum, start_time" > %sds_trace_%s'%(logdir, pid)], shell=True)
    subprocess.call(['cat %sds_trace  | grep " %s" >> %sds_trace_%s'%(logdir, pid, logdir, pid)], shell=True)

    ds_df = pd.read_csv('%s/ds_trace_%s'%(logdir, pid), sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=True, header=0)
    ds_df.sort_values('timestamp')
    ds_df = ds_df.dropna(axis=0, how='any')

    # Normalize traces time
    bpf_timebase_uptime = 0 
    bpf_timebase_unix = 0 
    with open(logdir + 'bpf_timebase.txt') as f:
        lines = f.readlines()
        bpf_timebase_unix = float(lines[-1].split(',')[0])
        bpf_timebase_uptime = float(lines[-1].split(',')[1].rstrip())
            
    offset = bpf_timebase_unix - bpf_timebase_uptime

    ds_norm_time_lists = []
    ds_raw_lines = ds_df.values.tolist()
    for line in ds_raw_lines:
        if len(line) != len(ds_trace_field):
            continue
        line[0] = (int(line[0])  / 10**9) + offset - cfg.time_base
        ds_norm_time_lists.append(line)

    ds_df = pd.DataFrame(data=ds_norm_time_lists, columns=ds_trace_field)
    ds_df['checksum'] = ds_df['checksum'].astype(int)
    ds_df['d_port'] = ds_df['d_port'].astype(int)

    # make sure data is correct fit in pid field.
    filter = ds_df['tgid'] == int(pid)
    ds_df = ds_df[filter]
    ds_df.to_csv(logdir + 'ds_trace_%s'%pid, mode='w', index=False, float_format='%.9f')

    filter = ds_df['net_layer'] == 300
    ds_tx_df = ds_df[filter]
    ds_tx_df.to_csv(logdir + 'ds_trace_pub_%s'%pid, mode='w', index=False, float_format='%.9f')

    filter = ds_df['net_layer'] == 1410
    ds_rx_df = ds_df[filter]
    ds_rx_df.to_csv(logdir + 'ds_trace_sub_%s'%pid, mode='w', index=False, float_format='%.9f') 

    ds_norm_time_lists = [ds_tx_df.values.tolist(), ds_rx_df.values.tolist()]

# DS trace 
# 0: Timestamp   # 3: tgid       # 6: payload     # 9: d_ip       # 12: start_time
# 1: comm        # 4: tid        # 7: s_ip        # 10: d_port
# 2: pkt_type    # 5: net_layer  # 8: s_port      # 11: Checksum 
 
# SOFA trace
# 0: timestamp   # 3: deviceId   # 6: bandwidth   # 9:  pid       # 12: category
# 1: event       # 4: copyKind   # 7: pkt_src     # 10: tid
# 2: duration    # 5: payload    # 8: pkt_dst     # 11: name
        
        # Convert to SOFA trace format
    SOFA_trace_lists = []
    sofa_trace_index = [0, -1, -1, 11, -1, 6, -1, 1, 1, -1, 3, 1, -1]
    SOFA_trace_lists.append(formatted_lines_to_trace(ds_norm_time_lists[0], sofa_trace_index))
    SOFA_trace_lists.append(formatted_lines_to_trace(ds_norm_time_lists[1], sofa_trace_index))
    SOFA_trace_lists.append(trace_calculate_bandwidth(ds_norm_time_lists[0]))
    SOFA_trace_lists.append(trace_calculate_bandwidth(ds_norm_time_lists[1]))

        # Convert to csv format which SOFA used to be stored as SOFA trace class  
    return [
            list_to_csv_and_traces(logdir, SOFA_trace_lists[0], 'dds_trace_tx%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[1], 'dds_trace_rx%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[2], 'dds_trace_tx_bandwidth%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[3], 'dds_trace_rx_bandwidth%s.csv'%pid, 'w')
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


def create_cnct_trace(cnct_list, is_sender, node_pid):
    cnct_trace_tmp = list(cnct_list)

    y_counter = node_pid[str(cnct_trace_tmp[3])]
    
    name = ''
    x = cnct_trace_tmp[0]
    y = y_counter

    if is_sender:
        name = str(cnct_trace_tmp[7]) + ':' + str(cnct_trace_tmp[8]) + ' | checksum = ' + str(cnct_trace_tmp[11])
        #y = (y_counter * 12 + 8)*0.01

    else:
        name = str(cnct_trace_tmp[9]) + ':' + str(cnct_trace_tmp[10]) + ' | checksum = ' + str(cnct_trace_tmp[11])
        #y = (y_counter * 12 + 4)*0.01

    trace = ds_cnct_trace_init()
    trace = [name, x, y]

    return trace
    
    


def ds_connect_preprocess(cfg):
    #all_nodes_socket = []
    node_pid = {} # used to find out the location of list where  
    all_send_socket = []
    all_recv_socket = []
    all_ds_df = pd.DataFrame([], columns=['timestamp', 'comm', 'pkt_type', 'tgid', 'tid', 'net_layer',\
                                          'payload', 's_ip', 's_port', 'd_ip', 'd_port', 'checksum', 'start_time'])
    

    counter = 0
    logdir = cfg.logdir

    print(logdir)

    nodes_record_dir = glob.glob('[0-9]*')

    for iter_dir in nodes_record_dir:
        node_pid[iter_dir] = counter
        send_socket = {}
        recv_socket = {}

        ds_df = pd.read_csv('%s/ds_trace_%s'%(iter_dir, iter_dir), sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=True, header=0, float_precision='round_trip')
        all_ds_df = pd.concat([ds_df, all_ds_df], ignore_index=True, sort=False)

        with open('%s/ds_trace_pub_%s'%(iter_dir, iter_dir),'r') as f_pub:
            f_pub.readline()        
            for line in f_pub.readlines():
                line = line.split(',')
                name = str(line[7]) + ':' + str(line[8])
                send_socket[name] = counter
            f_pub.close()
        all_send_socket.append(send_socket)

        with open('%s/ds_trace_sub_%s'%(iter_dir, iter_dir),'r') as f_sub:
            f_sub.readline()        
            for line in f_sub.readlines():
                line = line.split(',')
                name = str(line[9]) + ':' + str(line[10])
                recv_socket[name] = counter
            f_sub.close()
        all_recv_socket.append(recv_socket)

        counter += 1

    all_ds_df.sort_values(by='timestamp', inplace=True)
    all_ds_list = all_ds_df.values.tolist()

    filter = all_ds_df['net_layer'] == 300
    all_send_df = all_ds_df[filter]
    
    filter = all_ds_df['net_layer'] == 1410
    all_recv_df = all_ds_df[filter]


    all_send_list = all_send_df.values.tolist()
    all_recv_list = all_recv_df.values.tolist()
    send_find = [False] * len(all_send_list)
    recv_find = [False] * len(all_recv_list)
    all_send_index_list = []
    all_recv_index_list = []

    for index in range(len(all_send_list)):
        all_send_index_list.append([all_send_list[index], index])

    for index in range(len(all_recv_list)):
        all_recv_index_list.append([all_recv_list[index], index])


    cnct_trace = []
    cnct_traces =[]
    index_counter = 0
    node_index = {}

    recv_cnt_skip = 0
    latency = 1
    retry = True
    negative = False
    pre_sent_count = 0
    negative_max = 0
    positive_max = 0
    pre_recv_count = 0
    total_latency = 0
    while retry:
        retry = False

        for recv_cnt in range(recv_cnt_skip, len(all_recv_index_list)):
            total_latency, send_cnt = ds_find_sender(all_recv_index_list[recv_cnt], all_send_index_list, send_find, \
                                          latency, negative,total_latency)

            if send_cnt:
                send_select = all_send_index_list[send_cnt][1]
                recv_select = all_recv_index_list[recv_cnt][1]

                # find the max latency btween sender and receiver in given interval
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
                node2node = 'Node ' + str(all_send_index_list[send_cnt][0][3]) + \
                            ' to Node ' + str(all_recv_index_list[recv_cnt][0][3])
                
                if node2node in node_index:
                    cnct_trace = cnct_traces[node_index[node2node]]

                    cnct_trace.append(
                                  create_cnct_trace(all_send_index_list[send_cnt][0], 1, node_pid)
                                     )
                    cnct_trace.append(
                                  create_cnct_trace(all_recv_index_list[recv_cnt][0], 0, node_pid)
                                     )
                    cnct_trace.append(
                    ds_cnct_trace_init()
                                     )
                    cnct_traces[node_index[node2node]] = cnct_trace
                else:
                    node_index[node2node] = index_counter
                    index_counter += 1
                    cnct_traces.append([])
                    cnct_trace = cnct_traces[node_index[node2node]]

                    cnct_trace.append(
                                      create_cnct_trace(all_send_index_list[send_cnt][0], 1, node_pid)
                                     )
                    cnct_trace.append(
                                      create_cnct_trace(all_recv_index_list[recv_cnt][0], 0, node_pid)
                                     )
                    cnct_trace.append(
                    ds_cnct_trace_init()
                                     )
                    cnct_traces[node_index[node2node]] = cnct_trace

                del all_send_index_list[send_cnt]
                del all_recv_index_list[recv_cnt]
                send_find[send_select] = True
                recv_find[recv_select] = True
                recv_cnt_skip = recv_cnt
                retry = True
                break

        # scale out the searching domain
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
        #print(all_send_index_list[i][0])
        result_send_list.append(all_send_index_list[i][0])

    for i in range(len(all_recv_index_list)):
        result_recv_list.append(all_recv_index_list[i][0])


    ds_df_pub = pd.DataFrame(result_send_list, columns=['timestamp', 'comm', 'pkt_type', 'tgid', 'tid', 'net_layer',\
                                          'payload', 's_ip', 's_port', 'd_ip', 'd_port', 'checksum', 'start_time'])
    ds_df_sub = pd.DataFrame(result_recv_list, columns=['timestamp', 'comm', 'pkt_type', 'tgid', 'tid', 'net_layer',\
                                          'payload', 's_ip', 's_port', 'd_ip', 'd_port', 'checksum', 'start_time'])

    all_ds_df = pd.concat([ds_df_sub, ds_df_pub], ignore_index=True, sort=False)
    all_ds_df.sort_values(by='timestamp', inplace=True)
    all_ds_list = all_ds_df.values.tolist()
    for i in range(len(all_ds_list)):
        pass
        #print(all_ds_list[i])  
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
    
    print(node_pid)
    for node2node in node_index:

        cnct_trace = cnct_traces[node_index[node2node]]
        cnct_trace = pd.DataFrame(cnct_trace, columns = ['name','x','y'])

        sofatrace = SOFATrace()
        sofatrace.name = 'ds_connection_trace%d' % node_index[node2node]
        sofatrace.title = '%s' % node2node
        sofatrace.color = 'rgba(%s,%s,%s,0.8)' %(random.randint(0,255),random.randint(0,255),random.randint(0,255))
        sofatrace.x_field = 'x'
        sofatrace.y_field = 'y'
        sofatrace.data = cnct_trace
        traces.append(sofatrace)

      
    traces_to_json(traces, 'connect_view_data.js', cfg, '_connect')      
    return node_pid, all_send_socket, all_recv_socket
        


