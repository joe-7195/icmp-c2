```sh
# install python requirements
pip install scapy 

# kill icmp echo replies
echo "net.ipv4.icmp_echo_ignore_all=1" | sudo tee /etc/sysctl.d/10-disable-ping.conf
sudo sysctl -p

# start listener
python3 listener.py
```