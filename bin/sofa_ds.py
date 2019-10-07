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


def ds_preprocess(cfg):
    print(cfg.logdir)
    os.system('pwd')
    dds_logpath = cfg.logdir + "dds_finish/"
    os.chdir(dds_logpath)
    nodes_record_dir = glob.glob('[0-9]*')
    
    for i in range(len(nodes_record_dir)):
        #os.chdir(nodes_record_dir[i])
        cfg.logdir = './' + str(nodes_record_dir[i]) + '/'
        sofa_preprocess(cfg)
        #os.chdir('../')
        pass

