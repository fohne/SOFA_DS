#!/usr/bin/python3
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
from sofa_preprocess import sofa_preprocess
from sofa_ds_preprocess import ds_connect_preprocess

class DSTrace:
    data = []
    name = []
    title = []
    color = []
    x_field = []
    y_field = []

def ds_preprocess(cfg):
    save_logdir = cfg.logdir
    dds_logpath = cfg.logdir + "dds_finish/"
    os.chdir(dds_logpath)
    nodes_record_dir = glob.glob('[0-9]*')
    
    min_time = 0
    for i in range(len(nodes_record_dir)):
        time_fd = open('%s/sofa_time.txt' % nodes_record_dir[i])
        unix_time = time_fd.readline()
        unix_time.rstrip()
        if (min_time == 0):
            min_time = unix_time

        if unix_time < min_time:
            min_time = unix_time

    for i in range(len(nodes_record_dir)):
        time_fd = open('%s/sofa_time.txt' % nodes_record_dir[i])
        unix_time = time_fd.readline()
        unix_time.rstrip()
        cfg.cpu_time_offset = 0
        if (unix_time > min_time):
            cfg.cpu_time_offset = float(min_time) - float(unix_time)
            print(cfg.cpu_time_offset)

        cfg.logdir = './' + str(nodes_record_dir[i]) + '/'
        sofa_preprocess(cfg)
        cfg.logdir = save_logdir
    # return node_pid, all_send_socket, all_recv_socket
    node_pid, all_send_socket, all_recv_socket = ds_connect_preprocess(cfg)

