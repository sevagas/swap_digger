 
  --  swap_digger --

Author: Emeric NASI (Sio) at blog.sevagas.com

swap_digger is a bash script used to automate Linux swap analysis during post-exploitation or forensics. It automates swap extraction and searches for Linux user credentials, web forms credentials, web forms emails, http basic authentication, Wifi SSID and keys, etc.

For the most simple test, just run:

# ./swap_digger 
-> Will attempt to find Linux user clear text password


Other usages:

 ./swap_digger [ OPTIONS ]
 Options : 
  -x, --extended	Run extended tests on the target swap to retrieve other interesting data
		(web passwords, emails, wifi creds, etc)
  -g, --guessing	Try to guess potential passwords based on observations and stats
		Warning: This option is not reliable, it may dig more passwords as well as hundreds false positives.
  -h, --help	Display this help.
  -v, --verbose	Verbose mode.
  -l, --log	Log all output in a log file (protected inside the generated working directory).
  -c, --clean Automatically erase the generated working directory at end of script (will also remove log file)


 --

Blog posts about swap digging:
 - http://blog.sevagas.com/?Digging-passwords-in-Linux-swap

 --

Feel free to message me on my twitter account @EmericNasi


 --
