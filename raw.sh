#!/bin/bash
#!/bin/bash
clear
RED="\e[31m"
ORANGE="\e[33m"
BLUE="\e[94m"
GREEN="\e[92m"
STOP="\e[0m"


cd /home/pi/sentinel
printf "${GREEN}"
figlet "Launching Sentinel"
figlet "RAW MODE"


IsRunning=$(ps -aux | grep -c '[p]ython sentinel' )
echo "IsRunning: ${IsRunning}"

if [[ $IsRunning -gt "1" ]]; then
    echo ""
    echo "-------------------------------"
    echo "Sentinel is already running... "
    echo "-------------------------------"
    exit
fi

# Doing this manually so as not to interfere with hardline connection
sudo ifconfig wlan1 down
sudo iwconfig wlan1 mode monitor
sudo ifconfig wlan1 up



#echo "renaming old logfile"
#mv gpslog.txt  "gpslog$(date +%Y%m%d_%H%M).txt"



echo "Launch Sentinel"
rm -f *.log

sudo python sentinel.py --Raw Y --Friendly Y --Routers Y

#restart LAN services
#sudo systemctl restart NetworkManager
stty sane
printf "${STOP}"
