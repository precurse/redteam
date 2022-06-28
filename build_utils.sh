#!/bin/bash
set -ex
WEBDIR=`grep webroot config.yaml | awk '{print $2}'`

python3 generate_win_util_EfsPotato.py
python3 generate_win_util_PSLessExec.py
python3 generate_win_util_SQLClient.py
python3 generate_win_util_PowerupSQLScript.py

sudo mv win_pslessexec.exe ${WEBDIR}/tools/PSLessExec.exe
sudo mv win_sqlclient.exe ${WEBDIR}/tools/SQLClient.exe
sudo mv win_efspotato.exe ${WEBDIR}/EfsPotato.exe
sudo mv output_powerupsql.txt ${WEBDIR}/sql.txt
