# icmp c2

- simple icmp/ipv4 beacon for windows
- calls back to a linux server (i was not going to figure that out on windows)
- edit the destination ip in main.rs
- run these commands for the listener: (as root)
    ```sh
    # install python requirements
    pip install scapy 

    # kill icmp echo replies
    echo "net.ipv4.icmp_echo_ignore_all=1" | sudo tee /etc/sysctl.d/10-disable-ping.conf
    sudo sysctl -p

    # start listener
    python3 listener.py
    ```