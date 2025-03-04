# LightWave Server

## Sample Auth Exit Token Server

This repository contains a sample Auth Exit Token Server for LightWave Server. Its purpose is to demonstrate the basic interaction between LightWave Server and an Auth Exit token server.

Although the program is written in C and runs under the Guardian operating system, the specific Auth Exit functionality is straightforward enough to port to a C or Java program running under Open System Services. The only requirements are that the program be able to run in a Pathway Serverclass, to provide information about one or more tokens to be expected in a incoming REST request, and to verify token values received in a REST request, to a requestor like LightWave Server.

## Sample Contents

| Repository | NonStop filename | Description |
| --- | --- | --- |
| ./resources |  | Miscellaneous files |
| bldsrv.tacl | bldsrv | A TACL script for compiling stknsrv.c. |
| srvpwy.txt | srvpwy | A Pathway serverclass configuration for the stknsrv object as a serverclass. |
| ./src |  |  |
| stknsrv.c | stknsrvc | The NonStop C source code for the sample token server program. |
| README.md |  | This file |

## Building lwae.h

Compilation of the sample token server program requires the LightWave Auth Exits header file, lwae.h. The DDL source from which the header file is produced is included with the LightWave Server distribution, LWAEDDL.

``` tacl
tacl> volume aesample
tacl> ddl2
!?dictn, nosave
!?c lwaeh !
?source <lws-distro-svol>.lwaeddl
?exit
```

Where ```lws-distro-svol``` is the subvolume where the ```LWAEDDL``` file is stored.

DDL should compile ```LWAEDDL``` with no errors. ```lwaeh``` is then available for the ```stknsrvc``` compilation.

## Building the Token Server

After uploading the repository contents to the NonStop and compiling the ```LWAEDDL``` source to the ```lwae.h``` header file, the sample token server can be compiled.

``` tacl
tacl> volume aesample
tacl> run bldsrv
```

This step compiles the ```stknsrv.c``` source to the ```stknsrv``` program.

## Adding the Token Server to Pathway

LightWave Server communicates with the Token Server via Pathsend calls to the token server's serverclass.

A Pathway serverclass configuration for the sample ```stknsrv``` program is included in this repository:

``` pathcom
reset server
set server cpus 0:1
set server createdelay 0 secs
set server deletedelay 20 secs
set server highpin on
set server linkdepth 1
set server maxservers 20
set server maxlinks 4
set server numstatic 0
set server program stknsrv
set server tmf on
set server debug off
set server in $zhome
set server out $zhome
add server lws-tkn-svr
```

The name given to the serverclass, in this case ```lws-tkn-svr```, must be the same name specified in the LightWave Server Auth Exit Rule attached to the Access Control Policy for the Service for REST requests.

For further details on Auth Exit configuration, IPMs, and functionality, visit the online NuWave Documentation Center: https://docs.nuwavetech.com/.
