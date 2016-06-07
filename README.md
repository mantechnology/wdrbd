## Windows DRBD(Distributed Replicated Block Device)
                           
## Synopsis
WDRBD is a software-based, shared-nothing, replicated storage solution mirroring the content of block devices (hard disks, partitions, logical volumes etc.) between hosts by network transport(TCP/IP). 

## Motivation
DRBD has been developed and maintained by Linbit(http://www.drbd.org/), currently can be only used in linux platform, included in Linux kernel and then we have ported DRBD to Windows DRBD. Most of DRBD's functionallity is implemented to WDRBD, except for OS dependant things

## Build
- Environment : Windows 7 or higher
- tools : Visual Studio 2013 with update 5, Windows Driver Kit 6.3, Sygwin version 1.7.30, 
goto wdrbd9 directory and open wdrbd9.sln, config 32 or 64 properly, finally build drbd.sys

## Packaging
- WDRBD include install4j script source code. and then you can build WDRBD package individually.
- Alternativley you can download WDRBD builded-package from github's download link

## Installation
- select target platform. WDRBD packages(install4j) is composed of 32/64 bit environment. 
- install package (windows service(drbdService daemon) will be installed automatically)
- reboot required.

## Debug & Tests 
- setup WinDbg debugging environment
- copy drbd.sys to "install forder"/drbd/bin on target host.
- goto target host
- open cmd.exe window with administrator privilege
- chdir "install folder"/bin
- install.bat
- reboot

## Contributors
Man Technology Inc.(http://www.mantech.co.kr/)

## License
This project is licensed under the GPL v2
