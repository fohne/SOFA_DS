$WITH_SUDO python3 -m pip install --no-cache-dir ${PIP_PACKAGES}#!/bin/bash
WITH_SUDO="sudo -E" 
PIP_PACKAGES="numpy pandas matplotlib scipy networkx cxxfilt fuzzywuzzy sqlalchemy sklearn python-Levenshtein grpcio grpcio-tools matplotlib"
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install --no-cache-dir numpy pandas matplotlib scipy networkx cxxfilt fuzzywuzzy sqlalchemy sklearn python-Levenshtein grpcio grpcio-tools matplotlib"
