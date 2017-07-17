# swap_digger


Grep credentials information in Linux SWAP.
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

