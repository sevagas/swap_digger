![Bash version](https://img.shields.io/badge/Bash-4-brightgreen.svg) ![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

# swap\_digger

swap\_digger is a bash script used to automate Linux swap analysis for
post-exploitation or forensics purpose. It automates swap extraction and
searches for Linux user credentials, Web form credentials, Web form emails,
HTTP basic authentication, WiFi SSID and keys, etc.

![Sample run](/assets/swap_digger.png?raw=true "Sample run")

## Download and run the tool

### On your machine

Use the following commands to download and run the script on your machine:

```bash
alice@1nvuln3r4bl3:~$ git clone https://github.com/sevagas/swap_digger.git
alice@1nvuln3r4bl3:~$ cd swap_digger
alice@1nvuln3r4bl3:~$ chmod +x swap_digger.sh
alice@1nvuln3r4bl3:~$ sudo ./swap_digger.sh -vx
```

![Extended run](/assets/swap_digger_extended.png?raw=true "Extended run")

### On a mounted hard drive

To use swap\_digger on a mounted hard drive, do the following:

First, download the script using the following commands:
```bash
alice@1nvuln3r4bl3:~$ git clone https://github.com/sevagas/swap_digger.git
alice@1nvuln3r4bl3:~$ cd swap_digger
alice@1nvuln3r4bl3:~$ chmod +x swap_digger.sh
```

Then, find the target swap file/partition with:
```bash
alice@1nvuln3r4bl3:~$ sudo ./swap_digger.sh -S
``` 

Finally, analyze the target by running:
```bash
alice@1nvuln3r4bl3:~$ sudo ./swap_digger.sh -vx -r path/to/mounted/target/root/fs -s path/to/target/swap/device
```

### On a third party machine

Use the following commands to download and run the script on a third party machine (useful for pentests and CTFs):

```bash
alice@1nvuln3r4bl3:~$ wget https://raw.githubusercontent.com/sevagas/swap_digger/master/swap_digger.sh
alice@1nvuln3r4bl3:~$ chmod +x swap_digger.sh
alice@1nvuln3r4bl3:~$ sudo ./swap_digger.sh -vx
```

Note: Use the `-c` option to automatically remove the directory created by swap\_digger (`/tmp/swap_dig`).
 
 
## Simple run

If you only need to recover clear text Linux user passwords, simply run:
```bash
alice@1nvuln3r4bl3:~$ sudo ./swap_digger.sh
```

## Available options

All options:
```
 ./swap_digger.sh [ OPTIONS ]
 Options : 
  -x, --extended    Run Extended tests on the target swap to retrieve other interesting data
        (web passwords, emails, wifi creds, most accessed urls, etc)
  -g, --guessing  Try to guess potential passwords based on observations and stats
        Warning: This option is not reliable, it may dig more passwords as well as hundreds false positives.
  -h, --help    Display this help.
  -v, --verbose Verbose mode.
  -l, --log Log all outputs in a log file (protected inside the generated working directory).
  -c, --clean Automatically erase the generated working directory at end of script (will also remove log file)
  -r PATH, --root-path=PATH   Location of the target file-system root (default value is /)
        Change this value for forensic analysis when target is a mounted file system.
        This option has to  be used along the -s option to indicate path to swap device.
  -s PATH, --swap-path=PATH   Location of swap device or swap dump to analyse
        Use this option for forensic/remote analysis of a swap dump or a mounted external swap partition.
        This option should be used with the -r option where at least /<root-path>/etc/shadow exists.
  -S, --swap-search   Search for all available swap devices (use for forensics).
```
  
## Relevant resources

Blog posts about swap digging:
 - http://blog.sevagas.com/?Digging-passwords-in-Linux-swap

## Contact

Feel free to message me on my Twitter account [@EmericNasi](http://twitter.com/EmericNasi)

## License and credits

[The GNU General Public License version 3](https://opensource.org/licenses/GPL-3.0)

Copyright 2017 Emeric “Sio” Nasi ([blog](http://blog.sevagas.com))
