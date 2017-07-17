#!/bin/bash

declare -r  working_path="/tmp/swap_dig"
declare -r swap_dump_path="${working_path}/swap_dump.txt"
declare -r swap_wordlist_path="${working_path}/swap_wordlist.txt"
declare -r keepass_wordlist_path="${working_path}/keepass_wordlist.txt"
declare -a passwordList=()
declare -a guessedPasswordList=()
declare -a emailList=()

LOG_FILE=""
TARGET_ROOT_DIR="/"

# Output functions
out () {
	echo "$1"
	[ $LOG ] &&  { echo "$1" >> "$LOG_FILE"; }
}
note () {
	echo -e "\033[40m\033[01;36m Note:\033[0m $1"
	[ $LOG ] &&  { echo "Note: $1" >> "$LOG_FILE"; }
}
warning () {
	echo -e "\033[40m\033[01;33m Warning:\033[0m $1" >&2
	[ $LOG ] && { echo "Warning: $1" >> "$LOG_FILE"; }
}
error () {
	echo -e "\033[40m\033[1;31m [!] Error: $1\033[0m "  >&2
	[ $LOG ] &&  { echo " [!] Error: $1" >> "$LOG_FILE"; }
}
blue () {
	echo -e "\033[40m\033[01;36m  $1 \033[0m"
	[ $LOG ] && { echo  " $1 " >> "$LOG_FILE"; }
}

# usage : ask "QUESTION"
# NOTE : Ask for confirmations (y/Y -> return 0, else 1)
ask () {
	echo -n " $@" '[y/n] '
    echo -n " $@" '[y/n] ' >> "$working_path/output.log"
	local ans
	read ans
	case "$ans" in
		y*|Y*) return 0 ;;
		*) return 1 ;;
	esac
}


function init () {    
    # init
    #User must be root
    if [ `/usr/bin/id -u` -ne 0 ] # Use the fullpath of id (usually /usr/bin/id) & prevent aliasing of id
    then
        echo -e "\033[40m\033[1;31m  [!]  Sorry, this script needs root access -> abort! $1\033[0m "  >&2
        exit 1
    fi
    # Create test folder
    mkdir -p "$working_path"
    # Next 3 lines are for security
    chown root:root "$working_path"
    chmod 700 "$working_path"
    cd "$working_path" || { echo -e "\033[40m\033[1;31m  [!] Init error -> abort! $1\033[0m "  >&2; exit 1; }
    [ $LOG ]  && {
        now=`date +%Y-%m-%d.%H:%M:%S`
        LOG_FILE="$working_path/output_${now}.log"
    }
    
}

function end () { 
    out
    blue "SWAP Digger end, byebye! "
    out
    cd -
    [ $CLEAN ] && rm "$working_path" -rf
    exit 0
}




function dig_unix_passwd () {
    # Looking for linux account passwords (ubuntu)wc -l
    out
    out
    blue " ==== Linux system accounts ==="
    out
    out " [+] Digging linux accounts credentials..."
    SHADOWHASHES="$(cut -d':' -f 2 ${TARGET_ROOT_DIR}etc/shadow | grep -E '^\$.\$')"
    while read -r thishash; do
        DUMP=`grep -C40 "$thishash" "$swap_dump_path"`
        CTYPE="$(echo "$thishash" | cut -c-3)"
        SHADOWSALT="$(echo "$thishash" | cut -d'$' -f 3)"
        while read -r line; do
            #Escape quotes, backslashes, single quotes to pass into crypt
            SAFE=$(echo "$line" | sed 's/\\/\\\\/g; s/\"/\\"/g; s/'"'"'/\\'"'"'/g;')
            CRYPT="\"$SAFE\", \"$CTYPE$SHADOWSALT\""
            if [[ $(python2 -c "import crypt; print crypt.crypt($CRYPT)") == "$thishash" ]]; then
                #Find which user's password it is (useful if used more than once!)
                USER="$(grep "${thishash}" /etc/shadow | cut -d':' -f 1)"
                out "   [-] $USER:$line"
                passwordList=("${passwordList[@]}" "$line")
                break
            fi
        done <<< "$DUMP"
    done <<< "$SHADOWHASHES"
    
    nbHashes="$(cut -d':' -f 2 ${TARGET_ROOT_DIR}etc/shadow | grep -c -E '^\$.\$')"
    if [ ${#passwordList[@]} -lt $nbHashes ]
    then
        if john 2> /dev/null | grep -q cracker && ask "John was detect on the system, attempt to crack ${TARGET_ROOT_DIR}etc/shadow based on dumped swap wordlist?"
        then
            out
            out " [+] Digging linux accounts credentials method 2..."
            out " [+] Cracking linux account passwords using John."
            out "   [-] Generate wordlist file..."
            #uniq "$swap_dump_path" | sed '/^.\{40\}./d' > "$swap_wordlist_path" # account password are generally less then 40 char
            uniq -d "$swap_dump_path" | sed '/^.\{40\}./d' > "$swap_wordlist_path"  # You can use this line to go faster, account password are generally present more than once and less then 40 char
            echo "   [-] Cracking ${TARGET_ROOT_DIR}etc/shadow using wordlist... (This make take a some time)"
            if john "${TARGET_ROOT_DIR}etc/shadow" -wordlist:"$swap_wordlist_path"
            then
                OLDIFS=$IFS; IFS=$'\n';
                for creds in `john --show ${TARGET_ROOT_DIR}etc/shadow`
                do
                    out "   [-] Found -> $creds"
                    password=`echo $creds | cut -d ":" -f 2`
                    passwordList=("${passwordList[@]}" "$password") # Add found password to list
                done
                IFS=$OLDIFS
            
                if ask "Do you wan to delete john pot?"
                then
                    out "   [-] clean John pot..."
                    rm /root/.john/john.pot # use this to clear john db that now contains the clear text unix passwd
                fi
            fi
        fi
    fi
}


function dig_web_info () {
    # Looking for web passwords
    out
    out
    blue " ==== Web entered passwords and emails ==="
    out
    out " [+] Looking for web passwords method 1 (password in GET/POST)..."
    OLDIFS=$IFS; IFS=$'\n';
    for entry in `grep "&password=" "$swap_dump_path"`
    do
        out "   [-] $entry"
        password=`echo "$entry" | grep -o 'password=[^&]\+' | cut -f 2 -d '='`
        passwdSize=`echo $password | wc -c`
        if [[ $passwdSize -gt 6 ]]
        then
            passwordList=("${passwordList[@]}" "$password") # Add found password to list
        fi
    done
    IFS=$OLDIFS
    out
    out
    echo " [+] Looking for web passwords method 2 (JSON) ..."
    OLDIFS=$IFS; IFS=$'\n';
    for entry in `grep "password\",\"value\":\"" "$swap_dump_path"`
    do
        out "   [-] $entry"
        password=`echo "$entry" | grep -o 'password\",\"value\":\"[^\"]\+' | cut -f 5 -d '"' `
        passwdSize=`echo $password | wc -c`
        if [[ $passwdSize -gt 6 ]]
        then
            passwordList=("${passwordList[@]}" "$password") # Add found password to list
        fi

    done
    IFS=$OLDIFS
    out
    out
    echo " [+] Looking for web passwords method 3 (HTTP Basic Authentication) ..."
    OLDIFS=$IFS; IFS=$'\n';
    for entry in `grep -E '^Authorization: Basic.+=$' "$swap_dump_path" | cut -d' ' -f 3`
    do
        CREDS="$(echo "$entry" | base64 -d)"
        if [[ "$CREDS" ]]; then
            out "   [-] $CREDS"
            password=`echo "$CREDS" | cut -f 2 -d ":"`
            passwordList=("${passwordList[@]}" "$password") # Add found password to list
        fi
    done
    IFS=$OLDIFS
    # Looking for web entered email address
    out
    echo " [+] Looking for web entered emails..."
    OLDIFS=$IFS; IFS=$'\n';
    for entry in `grep -i 'email=' "$swap_dump_path" | grep @ | uniq`
    do
        email=`echo "$entry" | grep -o 'email=[^& ]\+' | cut -f 2 -d '='`
        emailList=("${emailList[@]}" "$email") # Add found email to list
    done
    IFS=$OLDIFS
    # Remove duplicates
    OLDIFS="$IFS"
    IFS=$'\n'
    emailList=(`for email in "${emailList[@]}"; do echo "$email" ; done | sort -du`)
    IFS="$OLDIFS"
    OLDIFS=$IFS; IFS=$'\n';
    for email in ${emailList[*]}
    do
        out "  ->  $email"
    done
    IFS=$OLDIFS

}


function dig_wifi_info () {
    # Looking for wifi credentials
    out
    out
    blue " ==== WiFi ==="
    out
    out " [+] Looking for wifi access points..."
    wifiNetworks=`grep -C 10  "Auto "  "$swap_dump_path" | grep -C 10 wireless | grep "Auto " | grep -v "NetworkManager" | cut -d " " -f 2,3,4 | sort | uniq`
    out "   [-] Potential wifi network list this computer accessed to:"
    OLDIFS=$IFS; IFS=$'\n';
    for accesspoint in $wifiNetworks
    do
        out "$accesspoint"
    done
    IFS=$OLDIFS
    out
    out " [+] Looking for potential Wifi passwords...."
    wifiPasswords1=`grep -C 10  "Auto "  "$swap_dump_path" | grep -A2 wpa-psk | egrep -v "wpa|addresses|NetworkManager|Auto|wireless|--|NMSetting" | sort | uniq`
    out "   [-] Potential wifi password list (use them to crack above networks)"
    OLDIFS=$IFS; IFS=$'\n';
    for password in $wifiPasswords1
    do
        out "$password"
    done
    IFS=$OLDIFS
        out
    out " [+] Looking for potential Wifi passwords method 2...."
    wifiPasswords2=`grep -o 'psk=.\+' "$swap_dump_path" | cut -f 2 -d '=' | sort | uniq`
    out "   [-] Potential wifi password list (use them to crack above networks)"
    OLDIFS=$IFS; IFS=$'\n';
    for password in $wifiPasswords2
    do
        out "$password"
    done
    IFS=$OLDIFS
    
}


function dig_keepass () {
    
    # Looking for keepass
    if  grep -C 8  "\.kdb" "$swap_dump_path" | grep -q KeePass
    then
        out
        out
        blue " ==== KeePass ==="
        out
        out " [+] Keepass detected!"
        out "   [-] Looking for KeePass DB name..."
        keepassDb=`grep -m1 ".*/.*\.kdb.$" "$swap_dump_path" `
        if [ -n  "$keepassDb" ]
        then
            out "   -> Found at: $keepassDb"
            #out "   [-] Generate wordlist file..."
            #strings --bytes=8 "$swap_dump_path" | uniq | sed '/^.\{40\}./d' > "$keepass_wordlist_path"  # We suppose no one use < 8char password if they know about keepass
        fi

    fi
}

function stringContain() { [ -z "${2##*$1*}" ]; }

function guessing () {

    out
    out
    blue " ==== Guessing ==="
    out
    # Remove duplicates
    OLDIFS="$IFS"
    IFS=$'\n'
    passwordList=(`for password in "${passwordList[@]}"; do echo "$password" ; done | sort -du`)
    IFS="$OLDIFS"

    note "Highly probable found passwords are:"
    OLDIFS=$IFS; IFS=$'\n';
    for passwd in ${passwordList[*]}
    do
        out "  ->  $passwd"
    done
    IFS=$OLDIFS

    if [ ${#passwordList[@]} -lt 2 ]
    then
        warning " 2 or more passwords are needed for guessing feature."
        return
    fi
    
    out
    out " [+] Start statistic guessing round 1... (wait for it)"
    OLDIFS=$IFS; IFS=$'\n';
    for passwd in ${passwordList[*]}
    do
        DUMP=`grep -C5 "$passwd" "$swap_dump_path" | egrep -vi "=|;|mail|session|nsI|login|number|desktop|<|/|\.com|--"` # We also remove special char responsible for too much false positive
        # Search for other words near password
        while read -r line; do
            passwdSize=`echo "$passwd" | wc -c`
            passwdSizeMin=$((passwdSize-2))
            passwdSizeMax=$((passwdSize+6))
            lineSize=`echo "$line" | wc -c`
            re='^[0-9]+$'
            if [[ $passwdSizeMin =~ $re ]] && [[ $lineSize =~ $re ]] && [ "$lineSize" -lt "$passwdSizeMax" ] && [ "$lineSize" -gt "$passwdSizeMin" ]
            then
                occurence=`grep -c "$line" "$swap_dump_path" 2>/dev/null`
                if [ $occurence -gt 0 ]
                then
                    [ $VERBOSE ] && echo "  [-] Potential password: $line"
                    guessedPasswordList=("${guessedPasswordList[@]}" "$line")
                fi
            fi
        done <<< "$DUMP"
    done
    IFS=$OLDIFS
    # Remove duplicates
    OLDIFS="$IFS"
    IFS=$'\n'
    guessedPasswordList=(`for password in "${guessedPasswordList[@]}"; do echo "$password" ; done | sort -du`)
    IFS="$OLDIFS"
    out

    out " [+] Start statistic guessing round 2... (waaaaait for it)"
    OLDIFS=$IFS; IFS=$'\n';
    for passwd in ${guessedPasswordList[*]}
    do
        # Add it to password list
        passwordList=("${passwordList[@]}" "$passwd")
        DUMP=`grep -C5 "$passwd" "$swap_dump_path" | egrep -vi "=|;|${passwd}|mail|session|nsI|login|number|desktop|<|/|,|\.com|--"` # We also remove special char responsibl for too much false positive and word itself
        # Search for other words near password
        while read -r line; do
            passwdSize=`echo $passwd| wc -c`
            passwdSizeMin=$((passwdSize-2))
            passwdSizeMax=$((passwdSize+6))
            lineSize=`echo $line | wc -c`
            if [[ $passwdSizeMin =~ $re ]] && [[ $lineSize =~ $re ]] && [ $lineSize -lt $passwdSizeMax ] && [ $lineSize -gt $passwdSizeMin ]
            then
                occurence=`grep -c "$line" "$swap_dump_path" 2>/dev/null`
                if [ $occurence -gt 1 ]
                then
                    [ $VERBOSE ] && echo "  [-] Potential password: $line"
                    passwordList=("${passwordList[@]}" "$line")
                fi
            fi
        done <<< "$DUMP"
    done
    IFS=$OLDIFS
    # Remove duplicates
    OLDIFS="$IFS"; IFS=$'\n'
    passwordList=(`for password in "${passwordList[@]}"; do echo "$password" ; done | sort -du`)
    IFS="$OLDIFS"
    out

    out " [+] Guessed potential passwords list:"
    OLDIFS=$IFS; IFS=$'\n';
    for passwd in ${passwordList[*]}
    do
        out "  ->  $passwd"
    done
    IFS=$OLDIFS
    out
    
}


function swap_digger () {
    out
    blue "- SWAP Digger -"
    out
    [ $LOG ] && note "Logging all outputs in $LOG_FILE"
    # Find swap partition
    [ -f "$swap_dump_path" ] || {
        out " [+] Looking for swap partition"
        swap=`cat ${TARGET_ROOT_DIR}etc/fstab | grep swap | cut -d " " -f 1`
        [ -b "$swap" ] || swap=`swapon -s | grep dev | cut -d " " -f 1`
        [ -b "$swap" ] || swap=`cat ${TARGET_ROOT_DIR}etc/fstab | grep swap -m 1 | cut -d " " -f 5`
        [ -b "$swap" ] ||  { error "Could not find swap partition -> abort!"; exit 1; }
        out "     -> Found swap at ${swap}"
        
        # TODO if TARGET_ROOT_DIR != /

        # Dumping swap strings
        out " [+] Dumping swap strings in $swap_dump_path ... (this make take some time) "
        strings --bytes=6 "$swap" > "$swap_dump_path"
    }

    # Let the fun begin!
    dig_unix_passwd
    [ $EXTENDED ] && {
        dig_web_info
        dig_wifi_info
        dig_keepass
    }
    [ $GUESSING ] && guessing

}


# display_usage function
display_usage ()
{
	echo
	echo "Usage: $0 [ OPTIONS ]"
	echo " Options : "
	echo "  -x, --extended	Run extended tests on the target swap to retrieve other interesting data"
	echo "		(web passwords, emails, wifi creds, etc)"
    echo "  -g, --guessing	Try to guess potential passwords based on observations and stats"
	echo "		Warning: This option is not reliable, it may dig more passwords as well as hundreds false positives."
	echo "  -h, --help	Display this help."
    echo "  -v, --verbose	Verbose mode."
    echo "  -l, --log	Log all output in a log file (protected inside the generated working directory)."
    echo "  -c, --clean Automatically erase the generated working directory at end of script (will also remove log file)"
    echo "  -r PATH, --root-path=PATH  Where is the target system root (default value is /)"
	echo "		Change this for forensic analysis when target is mounted"
    echo "		Option not implemented!!"
	echo
}




# Script will start here

# Transform long options to short ones
for arg in "$@"; do
  shift
  case "$arg" in
    "--clean") set -- "$@" "-c" ;;
    "--extended") set -- "$@" "-x" ;;
    "--guessing") set -- "$@" "-g" ;;
    "--log") set -- "$@" "-l" ;;
    "--help") set -- "$@" "-h" ;;
    "--verbose") set -- "$@" "-v" ;;
    "--root-path") set -- "$@" "-r" ;;
    "--"*) display_usage; exit 1 ;;
    *)        set -- "$@" "$arg"
  esac
done

# Parse short options
OPTIND=1
while getopts "cxglhv-r:" OPT
do  
   # options processing
	case $OPT in
        c) CLEAN=1 ;;
        l) LOG=1 ;;
        r) TARGET_ROOT_DIR="$OPTARG" ;;
		x) EXTENDED=1 ;;
        g) GUESSING=1 ;;
		h) display_usage | more;  exit 3  ;;
		v) VERBOSE=1 ;;
		*) display_usage; exit 1 ;;
	esac
done
shift $(expr $OPTIND - 1) # remove options from positional parameters

init
swap_digger
end


# TODO
# cat /proc/swaps
# PASS=
# /dev/tmpfs
