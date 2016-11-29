How to install Crypto-Detect.

1. Copy the crypto-detect files to C:\Crypto-Detect

2. Run Powershell as Administrator

3. Run the command below to allow the script to be run:
Set-ExecutionPolicy -ExecutionPolicy Unrestricted

4. CD to the script location (C:\Crypto-Detect) and run the script with command below:
.\Crypto-DetectV1.ps1

5. Crypto-Detect Menu will be shown.  Select the option to install locally, you will be 

guided/prompted through the menus.  I have tried to make this as simple as possible so 

less configration is needed.

6. Help file is in c:\Crypto-Detect, which explains each option in the main menu. Or 

select help in Main Menu.

7. Once installation complete, run the command below to stop unsigned scripts:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned