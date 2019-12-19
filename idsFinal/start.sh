#!/bin/bash

cd /home/debianml/idsFinal/tcpdump_and_cicflowmeter

sudo -E ./capture_interface_pcap.sh ens256 pcap > /dev/null 2>&1 &
sudo -E ./pickup_csv_files.sh csv/ > /dev/null 2>&1 &

cd /home/debianml/idsFinal/src

sudo -E python3 KafkaConsumer.py
#sudo -E python3 ConsumerConfusionMatrix.py

