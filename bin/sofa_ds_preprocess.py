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

# input 
#
# output
# result             processed traces
def formatted_lines_to_trace(data_in, index_tab, field_num, name_info="empty"):
    from sofa_preprocess import trace_init
    result = []

    trace = trace_init()
    for line in data_in:
       # line = line.split()
      #  print(line)
     #   pass

        # there is situation that data in the line not full-filled the line field which 
        # could made the number of fileds less than predefined field number, 
        # we need handle it or processing might failed. 
        data_in
        if len(line) != field_num:
            continue
        line 

        trace = [
                line[index_tab[0]] if index_tab[0] != -1 else trace[0],
                line[index_tab[1]] if index_tab[1] != -1 else trace[1] ,
                line[index_tab[2]] if index_tab[2] != -1 else trace[2] ,
                line[index_tab[3]] if index_tab[3] != -1 else trace[3] ,
                line[index_tab[4]] if index_tab[4] != -1 else trace[4] ,
                100,#line[index_tab[5]] if index_tab[5] != -1 else trace[5] ,
                line[index_tab[6]] if index_tab[6] != -1 else trace[6] ,
                line[index_tab[7]] if index_tab[7] != -1 else trace[7] ,
                line[index_tab[8]] if index_tab[8] != -1 else trace[8] ,
                line[index_tab[9]] if index_tab[9] != -1 else trace[9] ,
                line[index_tab[10]] if index_tab[10] != -1 else trace[10],
                line[index_tab[11]] if index_tab[11] != -1 else name_info,
                line[index_tab[12]] if index_tab[12] != -1 else trace[12]
                ]

        result.append(trace)
    return result




def ds_do_preprocess(cfg, logdir, pid):	
    from sofa_preprocess import sofa_fieldnames
    from sofa_preprocess import list_to_csv_and_traces
    
    ds_trace_field = \
['Timestamp', 'comm', 'pkt_type', 'tgid', 'tid', 'net_layer', 'payload',  'data_len', 's_ip', 's_port', 'd_ip', 'd_port', 'start_time']

    subprocess.call(['cat %sds_trace  | grep "%s" > %sds_trace_%s'%(logdir,pid,logdir,pid)], shell=True)
    # phase 2: use pid to filter out non-associated performance data
    with open('%s/ds_trace_%s'%(logdir, pid)) as ds_raw_fd:
        # Filter out record description 
        for i in range(0, 20):
            # line = ds_raw_fd.readline()
            tmp_line = ds_raw_fd.readline()
            # print(ll)
            if (tmp_line.find('TIME', 0, len(tmp_line))) > -1:
                break
        # Forward one step to the line next to the data header    
        ds_raw_lines = ds_raw_fd.readlines()


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
        for line in ds_raw_lines:
            tmp_line = line.split(',')
            #if(len(tmp_line)>8):
            #    print(tmp_line)
            tmp_line[0] = (int(tmp_line[0])  / 10**9) + offset - cfg.time_base
            ds_norm_time_lists.append(tmp_line)

        # Filter out specified  pid


        ds_df = pd.DataFrame(data=ds_norm_time_lists, columns=ds_trace_field)
        ds_df["tgid"]= ds_df["tgid"].astype(int) 
        filter = ds_df['tgid'] == int(pid)
        ds_df = ds_df[filter]
        ds_df["net_layer"]= ds_df["net_layer"].astype(int) 
        filter = ds_df['net_layer'] == 300
        ds_tx_df = ds_df[filter]
        filter = ds_df['net_layer'] == 1410
        ds_rx_df = ds_df[filter]
        ds_norm_time_lists = [ds_tx_df.values.tolist(), ds_rx_df.values.tolist()]


# ds_trace_field = 
# ['Timestamp', 'comm', 'pkt_type', 'tgid', 'tid', 'net_layer', 'payload',  'data_len', 's_ip', 's_port', 'd_ip', 'd_port', 'start_time']

# 0: timestamp   # 3: deviceId   # 6: bandwidth   # 9:  pid     # 12: category
# 1: event       # 4: copyKind   # 7: pkt_src     # 10: tid
# 2: duration    # 5: payload    # 8: pkt_dst     # 11: name
        
        # Translate to SOFA trace format
        SOFA_trace_lists = []
        index_tab = [0, -1, -1, 2, -1, 5, -1, -1, -1, -1, 3, -1, -1]
        SOFA_trace_lists.append(formatted_lines_to_trace(ds_norm_time_lists[0], index_tab, len(ds_trace_field), name_info="tx"))
        SOFA_trace_lists.append(formatted_lines_to_trace(ds_norm_time_lists[1], index_tab, len(ds_trace_field), name_info="rx"))
        SOFA_trace_lists_tmp = []

        for i in range(len(SOFA_trace_lists)):
            ds_df = pd.DataFrame(data=SOFA_trace_lists[i], columns=sofa_fieldnames)

        # Beaware the field used in x-y field for high chart should be numeric type 
        # or it won't display properly.
            ds_df["payload"] = pd.to_numeric(ds_df["payload"])
            SOFA_trace_lists_tmp.append(ds_df.values.tolist())

        
        # Translate to csv format which SOFA used to be stored as SOFA trace class  
        return [list_to_csv_and_traces(logdir, SOFA_trace_lists_tmp[0], 'dds_trace_tx%s.csv'%pid, 'w'),         list_to_csv_and_traces(logdir, SOFA_trace_lists_tmp[1], 'dds_trace_rx%s.csv'%pid, 'w')]


