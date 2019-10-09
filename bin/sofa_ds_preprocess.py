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

from sofa_config import *

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
    
    ds_trace_field = ['Timestamp', 'comm', 'pkt_type', 'tgid', 'tid', 'net_layer', 
                      'payload', 's_ip', 's_port', 'd_ip', 'd_port', 'checksum', 'start_time']

    subprocess.call(['echo "timestamp, comm, pkt_type, tgid, tid, net_layer, payload, s_ip,\
                      s_port, d_ip, d_port, checksum, start_time" > %sds_trace_%s'%(logdir, pid)], shell=True)
    subprocess.call(['cat %sds_trace  | grep "%s" >> %sds_trace_%s'%(logdir, pid, logdir, pid)], shell=True)

    ds_df = pd.read_csv('%s/ds_trace_%s'%(logdir, pid), sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=True, header=0)
    ds_df = ds_df.dropna(axis=0, how='any')
    # Normalize traces time
    with open(logdir + 'perf_timebase.txt') as f:
        lines = f.readlines()
        if len(lines) <= 3:
            print_warning('Recorded progrom is too short.')
            perf_timebase_uptime = 0 
            perf_timebase_unix = 0 
        elif lines[0].find('WARNING') != -1:
            perf_timebase_uptime = 0 
            perf_timebase_unix = 0 
        else:
            perf_timebase_uptime = float(lines[-2].split()[2].split(':')[0])
            perf_timebase_unix = float(lines[-1].split()[0])

    offset = perf_timebase_unix - perf_timebase_uptime

    ds_norm_time_lists = []
    ds_raw_lines = ds_df.values.tolist()
    for line in ds_raw_lines:
        if len(line) != len(ds_trace_field):
            continue
        line[0] = (int(line[0])  / 10**9) + offset - cfg.time_base
        ds_norm_time_lists.append(line)

    ds_df = pd.DataFrame(data=ds_norm_time_lists, columns=ds_trace_field)

    # Filter out non-associated performance data with pid
    filter = ds_df['tgid'] == int(pid)
    ds_df = ds_df[filter]

    filter = ds_df['net_layer'] == 300
    ds_tx_df = ds_df[filter]
    filter = ds_df['net_layer'] == 1410
    ds_rx_df = ds_df[filter]
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
    SOFA_trace_lists_tim = []
    for line in SOFA_trace_lists[1]:
        line[0] +=  4.039107
        SOFA_trace_lists_tim.append(line)
    SOFA_trace_lists[1] = SOFA_trace_lists_tim

        # Convert to csv format which SOFA used to be stored as SOFA trace class  
    return [
            list_to_csv_and_traces(logdir, SOFA_trace_lists[0], 'dds_trace_tx%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[1], 'dds_trace_rx%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[2], 'dds_trace_tx_bandwidth%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[3], 'dds_trace_rx_bandwidth%s.csv'%pid, 'w')
           ]



