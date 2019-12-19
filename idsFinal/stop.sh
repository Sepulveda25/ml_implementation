#!/bin/bash

sudo rm /home/debianml/idsFinal/tcpdump_and_cicflowmeter/csv/2019*
sudo killall capture_interfa
sudo killall pickup_csv_file
sudo killall inotifywait
