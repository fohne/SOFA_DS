import csv
import glob
import os
import re
import pandas as pd   
def dds_calc_topic_latency(cfg):
    logdir = cfg.logdir
    dds_trace_field = ['timestamp', 'comm', 'topic_name', 'tgid','tid','fid','topic_p','writer_p','data_p','winfo_p', 
                      'v_msg', 'gid_sys', 'gid_local', 'gid_seria', 'seq']

    all_dds_df = pd.DataFrame([], columns=dds_trace_field)
    #a = highchart_annotation_label()
    #c = json.dumps(a.__dict__)
    pid_yPos_dic = {} 
    yPos_cnt = 0
    pid_ip_dic = {}
    
    adjust_list = []
    en_adjust = 0
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

        dds_df = pd.read_csv('%s/dds_trace_%s'%(nd_dir_iter, nd_dir_iter), sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=True, header=0, float_precision='round_trip')

            



        all_dds_df = pd.concat([dds_df, all_dds_df], ignore_index=True, sort=False)

        yPos_cnt += 1

    all_dds_df.sort_values(by='timestamp', inplace=True)
    all_dds_df.to_csv('processed_dds_record', mode='w', index=False, float_format='%.9f')
    print('DDS raw data preprocess done')
    de_noise = all_dds_df.values.tolist()
    max_cnt = 0
    for command in command_dic:

        cnt = False

        for i in range(len(de_noise)):
            if de_noise[i][1].find(command) !=-1:
                cnt = i

                break
        if cnt and cnt > max_cnt:
            max_cnt = cnt

    de_noise = de_noise[max_cnt:]
    all_dds_df = pd.DataFrame(de_noise, columns=dds_trace_field)


    y = [0,0,0,0,0,0,0,0,0,0,0,0,0]

  

### Not really important, just nickname for sender and receiver records.
    filter = all_dds_df['fid'] == 13
    all_send_df = all_dds_df[filter]
    #all_send_df = all_send_df.apply(lambda x: x if (x['comm'].find('xmit.user')>-1) else None, result_type='broadcast', axis=1)
    all_send_df = all_send_df.dropna()	
    all_send_list = all_send_df.values.tolist()

    filter = all_dds_df['fid'] == 21
    all_recv_df = all_dds_df[filter]
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
    feature_send_dic = {}
    for send_cnt in range(len(all_send_index_list)):
        send_tmp = all_send_index_list[send_cnt][0]
        send_feature_pattern = str(send_tmp[11]) + str(send_tmp[12]) + \
                               str(send_tmp[13]) + str(send_tmp[14])
        if send_feature_pattern not in feature_send_dic:
            feature_send_dic[send_feature_pattern] = [1, send_cnt]
            send_canidate[send_cnt] = True
        else:
            feature_send_dic[send_feature_pattern][0] += 1
            send_canidate[feature_send_dic[send_feature_pattern][1]] = False
    #        send_canidate[send_cnt] = True
                             
    recv_canidate = [False] * len(all_recv_list)
    feature_recv_dic = {}
    for recv_cnt in range(len(all_recv_index_list)):
        recv_tmp = all_recv_index_list[recv_cnt][0]
        recv_feature_pattern = str(recv_tmp[11]) + str(recv_tmp[12]) + \
                               str(recv_tmp[13]) + str(recv_tmp[14])
        if recv_feature_pattern not in feature_recv_dic:
            feature_recv_dic[recv_feature_pattern] = [1, recv_cnt]
            recv_canidate[recv_cnt] = True
        else:
            feature_recv_dic[recv_feature_pattern][0] += 1
            recv_canidate[feature_recv_dic[recv_feature_pattern][1]] = False
#            recv_canidate[recv_cnt] = True

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
                continue

            recv_tmp = all_recv_index_list[recv_cnt][0]
            recv_feature_pattern = str(recv_tmp[11]) + str(recv_tmp[12]) +  \
                                   str(recv_tmp[13]) + str(recv_tmp[14])

            sfind = False
            for send_cnt in range(len(all_send_index_list)):
                if not send_canidate[all_send_index_list[send_cnt][1]]:
                #if  send_find[all_send_index_list[send_cnt][1]]:
                    continue

                send_tmp = list(all_send_index_list[send_cnt][0])
                if  recv_tmp[0] - send_tmp[0] < 0:
                    pass #break
                send_feature_pattern = str(send_tmp[11]) + str(send_tmp[12]) + \
                                       str(send_tmp[13]) + str(send_tmp[14])

                if (recv_feature_pattern == send_feature_pattern):
                    sfind = send_cnt
                    match_cnt += 1

                    acc_id = "Topic:["+str(send_tmp[2]) +"] from " + str(send_tmp[1]) + " to " + str(recv_tmp[1])
                    if acc_id not in accounting:
                        accounting[acc_id] = {}
                        accounting[acc_id]['latency'] = []

                    accounting[acc_id]['latency'].append(recv_tmp[0] - send_tmp[0])

                  
                    break;


### ------- Account ambibuous record (need to be filter out before making connection trace)
            if sfind:

                send_select = all_send_index_list[sfind][1]
                recv_select = all_recv_index_list[recv_cnt][1]

                del all_send_index_list[sfind]
                send_find[send_select] = True
                recv_find[recv_select] = True


# --------- END if sfind:
# ----- END for recv_cnt in range(recv_cnt_skip, len(all_recv_index_list)):
# - END while retry:



    result_send_list = []
    result_recv_list = []
    for i in range(len(all_send_index_list)):
        result_send_list.append(all_send_index_list[i][0])

    for i in range(len(all_recv_index_list)):
        result_recv_list.append(all_recv_index_list[i][0])





    recv_nfind = [not i for i in recv_find]
    send_nfind = [not i for i in send_find]

    recv_not_find = all_recv_df[recv_nfind]
    send_not_find = all_send_df[send_nfind]
    all_not_df = pd.concat([send_not_find, recv_not_find], ignore_index=True, sort=False)

    all_not_df.sort_values(by='timestamp', inplace=True)
    all_not_df.to_csv('nfound', mode='w', index=False, float_format='%.9f')


          
    for acc_id in accounting:

        print(acc_id+'\n')

        df = pd.DataFrame(accounting[acc_id]['latency'])
        print('Latency')
        print('%%.25: %f'%(df.quantile(0.25)))
        print('%%.50: %f'%(df.quantile(0.5)))
        print('%%.75: %f'%(df.quantile(0.75)))
        print('%%.95: %f'%(df.quantile(0.95)))
        print('mean: %f'%(df.mean()))

    print('\nTotal match count: %s'%match_cnt)
