 
  --  swap_digger --

Author: Emeric NASI (Sio) at blog.sevagas.com

swap_digger is a bash script used to automate Linux swap analysis during post-exploitation or forensics. It automates swap extraction and searches for Linux user credentials, web forms credentials, web forms emails, http basic authentication, Wifi SSID and keys, etc.

For the most simple test, just run:

# ./swap_digger 
-> Will attempt to find Linux user clear text password


Other usages:

 ./swap_digger [ OPTIONS ]
 Options : 
  -x, --extendedRun Extended tests on the target swap to retrieve other interesting data
		(web passwords, emails, wifi creds, most accessed urls, etc)
  -g, --guessing  Try to guess potential passwords based on observations and stats
		Warning: This option is not reliable, it may dig more passwords as well as hundreds false positives.
  -h, --help	Display this help.
  -v, --verbose	Verbose mode.
  -l, --log	Log all outputs in a log file (protected inside the generated working directory).
  -c, --clean Automatically erase the generated working directory at end of script (will also remove log file)
  -r PATH, --root-path=PATH   Location of the target file-system root (default value is /)
		Change this value for forensic analysis when target is a mounted file system.
		This option has to  be used along the -s option to indicate path to swap device.
  -s PATH, --swap-path=PATH   Location of swap device or swap dump to analyse
		Use this option for forensic/remote analysis of a swap dump or a mounted external swap partition.
		This option should be used with the -r option where at least /<root-path>/etc/shadow exists.
  -S, --swap-search   Search for all available swap devices (use for forensics).
  
 --

Blog posts about swap digging:
 - http://blog.sevagas.com/?Digging-passwords-in-Linux-swap

 --

Feel free to message me on my twitter account @EmericNasi


 --
