@ECHO OFF
REM This file was last updated 04/09/2015

ECHO Create a list of all the shares you'll need to add back later...
net share >> C:\windows\1-PreventCrypto-PreviousShares.txt

ECHO Kill all current sessions...
net session /delete /y

ECHO Remove all shares...
REM Copy the lines below for every share name on this server, in this example shares are 'home' and 'public'
REM This simply removes the share so additional files cannot get encrypted
REM It does not delete the actual folder, but you will have to add the share back later
net share home /delete /y
net share public /delete /y
net share _A_Crypto /delete /y

ECHO Backup method to prevent access to shares...
REM You will have to re-enable these Windows firewall rules later
REM For servers in domain zone
netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv4-In)" new enable=no profile=domain
netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv6-In)" new enable=no profile=domain
netsh advfirewall firewall set rule name="File and Printer Sharing (LLMNR-UDP-In)" new enable=no profile=domain
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Datagram-In)" new enable=no profile=domain
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Name-In)" new enable=no profile=domain
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=no profile=domain
netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" new enable=no profile=domain
netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC)" new enable=no profile=domain
netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC-EPMAP)" new enable=no profile=domain
REM Just incase server is in private zone
netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv4-In)" new enable=no profile=private
netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv6-In)" new enable=no profile=private
netsh advfirewall firewall set rule name="File and Printer Sharing (LLMNR-UDP-In)" new enable=no profile=private
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Datagram-In)" new enable=no profile=private
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Name-In)" new enable=no profile=private
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=no profile=private
netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" new enable=no profile=private
netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC)" new enable=no profile=private
netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC-EPMAP)" new enable=no profile=private
REM Just incase server is in public zone
netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv4-In)" new enable=no profile=public
netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv6-In)" new enable=no profile=public
netsh advfirewall firewall set rule name="File and Printer Sharing (LLMNR-UDP-In)" new enable=no profile=public
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Datagram-In)" new enable=no profile=public
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Name-In)" new enable=no profile=public
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=no profile=public
netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" new enable=no profile=public
netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC)" new enable=no profile=public
netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC-EPMAP)" new enable=no profile=public

ECHO Notify any admin currently logged on this server...
C:\windows\psexec.exe -d -i 0 -accepteula C:\windows\system32\cscript.exe /nologo C:\Windows\1-PreventCrypto-Message.vbs

REM Optional, Shutdown this server in 10 seconds...
REM C:\windows\psshutdown.exe -f -k -t 10 -accepteula -m "Shutdown initiated by 1-PreventCrypto.bat via FSRM"

PAUSE
EXIT