<#
    .Synopsis

    Crypto-Detect will install FSRM on a local or remote server when specified. You can also Detect Mapped drives that have been configured by Group Policies on the domain. 
    There is an option to test the FSRM configuration on the local or remote server.

    The folders do not need to be mapped for this to work. Any Shared folder will work with Crypto-Detect.

    .DESCRIPTION
    
    [1] Install FSRM on Local server
        Installs FSRM on the local server and imports the File Group definitions and a screen template.
        Checks to see if FSRM is already installed and if not it will be installed first.
        You will be prompted to add an email SMPT server, admin email address that will be used to receive the alerts and a From address also.
        Next you will be prompted to add the Mapped drive folder paths for each share you wish to protect.

    [2] Detect all Mapped drives on Domain
        This will run the Get-GPPDriveMaps.ps1 script which will be in the same directory at the DetectCrypto script.
        This will prompt for a Domain Controller in the current domain and search and list all drives which have been mapped via GPO.
     
    [3] Install FSRM on Remote server
        This allows you to Install FSRM and imports the File Group definitions and a screen template on a remote server in the domain once specified.
        Checks to see if FSRM is already installed and if not it will be installed first.
        You will be prompted to add an email SMPT server, admin email address that will be used to recieve the alerts and a From address also.
        Next you will be prompted to add the Mapped drive folder paths for each share you wish to protect.

    [4] Set Email Config on FSRM
        Allows you to change the email configuration settings for SMTP server, default receipt address and the From address for a local or Remote server.
        

    [5] Protect File share on Local server
        Allows you to update the local FSRM server with new File Screens to protect Shared/Mapped drive folder paths.

    [6] Protect File Share on Remote server
        Allows you to update a Remote FSRM server with new File Screens to protect Shared/Mapped drive folder paths.

    [7] Test Crypto Detect
        Tests the setup of the FSRM server, which will send an email after protecting a dummy folder c:\Test_Share and adding a +recover+ file.
     
    [8] Update Crypto Definitions
        Allows you to update the crypto definitions on a local or remote server.  This is useful when an Ransomware Crypto-Detect has not seen before, which can
        be added to the FSRM server detection process.  You would have to do this on each server. 


    .LINK
    https://community.spiceworks.com/how_to/100368-cryptolocker-canary-detect-it-early
    http://jpelectron.com/sample/Info%20and%20Documents/Stop%20crypto%20badware%20before%20it%20ruins%20your%20day/1-PreventCrypto-Readme.htm
        
    .EXAMPLE
    Example of how to use this cmdlet

    .EXAMPLE
    Another example of how to use this cmdlet


#>
function Install-Crypto {

  $FSRMInstalled = Get-WindowsFeature -Name FS-Resource-Manager | Select-Object Installed
  
  ## Checks if FSRM is installed already, if not - Install FSRM
  if ($FSRMInstalled.Installed -eq $true) { Write-Warning 'FSRM already installed, will now install File screens and Templates' }
  if ($FSRMInstalled.Installed -eq $false) { Install-WindowsFeature –Name FS-Resource-Manager –IncludeManagementTools -Verbose

    Write-Host ''
    Write-Host 'FSRM Installed' -ForegroundColor 'Green'
    Write-Host '' }

  ## IMPORTS FILEGROUP

  If ($Choice -eq '3'){Write-Host 'You pressed 3'}

  If ($input -eq '3'){filescrn.exe filegroup import /file:\\$Remote\c$\Crypto_filegroup.xml /filegroup:"1-PreventCrypto"}
  Else{filescrn.exe filegroup import /file:$PSScriptRoot\Crypto_filegroup.xml /filegroup:"1-PreventCrypto"}

  Write-Host ''
  Write-Host 'File Group 1-PreventCrypto IMPORTED' -ForegroundColor 'Green'
  Write-Host ''

  ##IMPORTS SCREEN TEMPLATE
  If ($Choice -eq '3'){filescrn.exe template import /file:\\$Remote\c$\filescreenCrypto.xml /template:"1-PreventCrypto"}
  Else {filescrn.exe template import /file:$PSScriptRoot\filescreenCrypto.xml /template:"1-PreventCrypto"}

  Write-Host ''
  Write-Host 'Screen Template 1-PreventCrypto IMPORTED' -ForegroundColor 'Green'
  Write-Host ''

}

function Show-Title {

  [console]::ResetColor()
  Write-Host 'Matt Skews' -ForegroundColor white
  Write-Host '█▀▀ █▀▀█ █░░█ █▀▀█ ▀▀█▀▀ █▀▀█    █▀▀▄ █▀▀ ▀▀█▀▀ █▀▀ █▀▀ ▀▀█▀▀    ▄█░ ░ █▀▀█ ' -ForegroundColor 'green'
  Write-Host '█░░ █▄▄▀ █▄▄█ █░░█ ░░█░░ █░░█ ██ █░░█ █▀▀ ░░█░░ █▀▀ █░░ ░░█░░    ░█░ ░ █▄▀█ ' -ForegroundColor 'green'
  Write-Host '▀▀▀ ▀░▀▀ ▄▄▄█ █▀▀▀ ░░▀░░ ▀▀▀▀    ▀▀▀░ ▀▀▀ ░░▀░░ ▀▀▀ ▀▀▀ ░░▀░░    ▄█▄ █ █▄▄█ ' -ForegroundColor 'green'
  Write-Host '                                                                     Beta 1 '

}

function Show-Menu {
  param(
    [string]$Title = 'Crypto Detect'
  )
  Clear-Host
  Show-Title
  Write-Host '---------------------------- Main Menu ------------------------------------' -ForegroundColor 'green'
  Write-Host ''
  Write-Host '[1] Install FSRM on Local server' -ForegroundColor 'green'
  Write-Host '[2] Detect all Mapped drives on Domain' -ForegroundColor 'green'
  Write-Host '[3] Install FSRM on Remote server' -ForegroundColor 'green'
  Write-Host '[4] Set Email Config on FSRM' -ForegroundColor 'green'
  Write-Host '[5] Protect File share on Local server' -ForegroundColor 'green'
  Write-Host '[6] Protect File Share on Remote server' -ForegroundColor 'green'
  Write-Host '[7] Test Crypto Detect' -ForegroundColor 'green'
  Write-Host '[8] Update Crypto Definitions' -ForegroundColor 'green'
  Write-Host ''
  Write-Host '[9] Help'
  Write-Host '[Q] Press Q to Quit'
  Write-Host ''
}

function Install-Screen {
  param(
    [string]$SubTitle = 'Crypto Detect'
  )

  Write-Host '-------------------------- Protect Shared Drive ---------------------------' -ForegroundColor 'yellow'
  Write-Host ''
  Write-Host 'You will now be asked the Path of each shared drive that ' -ForegroundColor 'yellow'
  Write-Host 'requires Crypto-Detect [File Screen].  EXAMPLE:   D:\Public' -ForegroundColor 'yellow'
  Write-Host ''
  Write-Host 'List of Shares on current server' $env:computername


  ## LISTS ALL SHARES ON SERVER
  Get-WmiObject -Class 'Win32_Share' | Format-Table -AutoSize

  ## foreach ($objItem in $colItems) {write-host  $objItem.Path, $objItem.WorkingSetSize -foregroundcolor 'yellow'}

  do {

    ##HOW MANY SHARES QUESTION
    do { $value1 = Read-Host -Prompt 'How many shares require Crypto-Detect'
      if ($value1 -notin (0..100)) { Write-Warning 'Use a number' }
    }
    while ((1..100) -notcontains $value1)


    foreach ($i in 1..$value1) {

      ##PRMPT USER FOR SHARE PATH  ======== [[CRAZY SCRIPT STARTS]]============
      Write-Host ''
      $Share1 = Read-Host -Prompt 'Enter Share Path'


      ##CREATES FILE WITH RANDOM 3 NUMBERS AND ADDS THE SHARE REMOVE COMMAND to BAT FILE
      $random = Get-Random -min 100 -max 900
      $BatchFilename = New-Item "C:\Windows\Scripts\1-PreventCrypto-$random.bat" -Type file -Force -Value "net share $share1 /delete /y"
      $fileTemplateName = "1-PreventCrypto-$random"
      $fileGroupName = '1-PreventCrypto'
      ## $batchConf | Out-File -Encoding ASCII $batchFilename
      $cmdConfFilename = "$env:Temp\cryptoblocker-cmdnotify.txt"
      $cmdConfFilename2 = "$env:Temp\cryptoblocker-cmdnotify2.txt"


      ## SETS CONFIG FOR TEMPLATE COMMAND
       $cmdConf = @"
Notification=C
RunLimitInterval=0
Command=$batchFilename
Arguments=[Source Io Owner]
MonitorCommand=Enable
Account=LocalSystem
"@

      ## SETS CONFIG FOR EMAIL ALERT (could be set in an txt file?)
      $cmdConf2 = @"
Notification=m
To=[Admin Email]
From=$Fromaddress
Subject=URGENT - Cryptolocker virus DETECTED on [Server]
Message=User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server.. \
\
WARNING: The share [File Screen Path] has been un-shared on file server [Server] and will need re-sharing once crypto-virus has been remediated. \
\
See Help file on server [Server] - c:\CryptoDetect
"@

      $cmdConf | Out-File $cmdConfFilename
      $cmdConf2 | Out-File $cmdConfFilename2

      ## CREATES TEMPLATE

      ##     &filescrn.exe Template Add "/Add-Notification:m,$cmdConfFilename2" "/Add-Notification:C,$cmdConfFilename" "/Template:$fileTemplateName" "/Add-Filegroup:$fileGroupName" /Type:Passive

      ## CREATES SCREEN

      ##     &filescrn.exe Screen Add "/Path:$Share1" "/SourceTemplate:$fileTemplateName"
      ## Set-FsrmFileScreen $Share1 -Notification $Email

      filescrn Screen Add /Path:$Share1 /Type:Passive /Add-Filegroup:"1-PreventCrypto" "/Add-Notification:C,$cmdConfFilename" "/Add-Notification:m,$cmdConfFilename2"

      ## Set-FSRMFilescreen -Path "$share1" -Notification $Email2



      ## ==========   [[CRAZY SCRIPT ENDS]] ============
    }

    ## ANYMORE SHARES?
    [console]::ResetColor()
    Write-Host ''
    Write-Host 'Do you need to add any more Shares' -NoNewline
    Write-Host ' [yes]' -ForegroundColor Yellow -NoNewline
    Write-Host ' or' -NoNewline
    Write-Host ' [no (Default)]' -ForegroundColor Yellow -NoNewline
    $continue = Read-Host -Prompt ' '
    [console]::ResetColor()


  }
  while ($continue -match 'yes|y')


}

function Test-Crypto {

  ### TEST DUMMY FILE

  Write-Host 'This test will:' -ForegroundColor 'yellow'
  Write-Host 'Create temerary share [C:\Test_Share]' -ForegroundColor 'yellow'
  Write-Host 'Create a File screen for the test share in FSRM' -ForegroundColor 'yellow'
  Write-Host 'Create a txt file named [+recover+.txt]' -ForegroundColor 'yellow'
  Write-Host 'The Share and File screen will be removed at end of test' -ForegroundColor 'yellow'
  Write-Host ''

  ##DO THEY WANT TO RUN THE TEST QUESTION

  Write-Host 'Do you want to run the TEST' -NoNewline
  [console]::ForegroundColor = 'yellow'
  Write-Host ' [yes]' -NoNewline
  [console]::ResetColor()
  Write-Host ' or' -NoNewline
  [console]::ForegroundColor = 'yellow'
  Write-Host ' [no]' -NoNewline
  [console]::ResetColor()
  $test = Read-Host -Prompt ' '
  [console]::ResetColor()

  if ($test -match 'yes|y') {

      New-Item C:\Test_Share -Type directory
      net.exe share Test_Share=c:\Test_Share /remark:"Test Share"

  $TestShare = 'C:\Test_Share'

        $random = Get-Random -min 100 -max 900
      $BatchFilename = New-Item "C:\Windows\Scripts\1-PreventCrypto-$random.bat" -Type file -Force -Value "net share $TestShare /delete /y"
      $fileTemplateName = "1-PreventCrypto-$random"
      $fileGroupName = '1-PreventCrypto'
      ## $batchConf | Out-File -Encoding ASCII $batchFilename
      $cmdConfFilename = "$env:Temp\cryptoblocker-cmdnotify.txt"
      $cmdConfFilename2 = "$env:Temp\cryptoblocker-cmdnotify2.txt"


      ## SETS CONFIG FOR TEMPLATE COMMAND
       $cmdConf = @"
Notification=C
RunLimitInterval=0
Command=$batchFilename
Arguments=[Source Io Owner]
MonitorCommand=Enable
Account=LocalSystem
"@

      ## SETS CONFIG FOR EMAIL ALERT (could be set in an txt file?)
      $cmdConf2 = @"
Notification=m
To=[Admin Email]
From=$Fromaddress
Subject=URGENT - Cryptolocker virus DETECTED on [Server]
Message=User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server.. \
\
WARNING: The share [File Screen Path] has been un-shared on file server [Server] and will need re-sharing once crypto-virus has been remediated. \
\
See Help file on server [Server] - c:\CryptoDetect
"@

      $cmdConf | Out-File $cmdConfFilename
      $cmdConf2 | Out-File $cmdConfFilename2

      ## CREATES TEMPLATE

      ##     &filescrn.exe Template Add "/Add-Notification:m,$cmdConfFilename2" "/Add-Notification:C,$cmdConfFilename" "/Template:$fileTemplateName" "/Add-Filegroup:$fileGroupName" /Type:Passive

      ## CREATES SCREEN

      ##     &filescrn.exe Screen Add "/Path:$Share1" "/SourceTemplate:$fileTemplateName"
      ## Set-FsrmFileScreen $Share1 -Notification $Email

      filescrn Screen Add /Path:$TestShare /Type:Passive /Add-Filegroup:"1-PreventCrypto" "/Add-Notification:C,$cmdConfFilename" "/Add-Notification:m,$cmdConfFilename2"


   ## TEST BEGINS
    [console]::ForegroundColor = 'gray'


    ##filescrn.exe screen add /path:C:\Test_Share /type:passive /sourcetemplate:"1-PreventCrypto"

    New-Item $TestShare\+Recover+.txt -Type File

    ##DELETE THE TEST FILES AND SCREEN
    filescrn screen delete /path:C:\Test_Share /quiet

    net share Test_Share /delete

    Remove-Item C:\Test_Share -Recurse


     [console]::ResetColor()
    Write-Host ''
    Write-Host 'You should now recieve an email alert from' -ForegroundColor 'yellow' -NoNewline
    Write-Host " $Fromaddress " -ForegroundColor 'white' -NoNewline
    Write-Host 'advising of a' -ForegroundColor 'yellow' -NoNewline
    Write-Host ' +recover+.txt' -ForegroundColor 'white' -NoNewline
    Write-Host ' file in' -ForegroundColor 'yellow' -NoNewline
    Write-Host ' C:\Test_Share' -ForegroundColor 'white' -NoNewline
    Write-Host ''

  }
}

function Get-Remote {

  ## CONNECTING TO A REMOTE SERVER
  Write-Host ''
  Write-Host '[Q] Return to Main Menu'
  do {

    Write-Host ''
    $Global:Remote = Read-Host 'Name of Remote Server'
    $Error.Clear()

    ### If they press Q. Don't run this till next Else.
    if ($Remote -notlike 'q') {

      ## TESTS CONNECTION TO REMOTE SERVER
      $Connection = Test-Connection -ComputerName $Remote -Count 1

    }
    ## if they dont press Q, then do nothing.. (Else) .. carry on...
    else {}
  }
  ## IF CONNECTION FAILES RETURN TO START OF 'DO', UNLESS THEY PRESS Q
  while (($Connection -eq $null) -or ($Connection -eq $false) -and ($Remote -notlike 'q'))

  ## CLEAR ALL ERRORS
  $Error.Clear()
}

function Set-Email {

  ##SETS SMTP SERVER AND NOTIFICATION LIMITS TO 2
  $smtp = Read-Host 'Smtp server'
  $smtp = $smtp.Replace(' ' , '')
  Set-FsrmSetting -SmtpServer $smtp
  Set-FsrmSetting -CommandNotificationLimit 2 -EmailNotificationLimit 2 -EventNotificationLimit 2

  ##SETS [TO] ADDRESS
  do{
     $Global:Adminaddress = Read-Host 'Defualt recipient [Admin] address'
     $Global:Adminaddress = $Global:Adminaddress.Replace(' ' , '')
     if(($Adminaddress -notmatch "@") -or ($Adminaddress -notlike "q")){ Write-Warning 'Not valid email address'}
     Else {Set-FsrmSetting -AdminEmailAddress $Adminaddress}
    }
  while(($Adminaddress -notmatch "@") -and ($Adminaddress -notlike "q"))

  

  ##SETS [FROM] ADDRESS
  Do{
     $Global:Fromaddress = Read-Host 'Enter [From] email address eg:CRYPTO_ALERT@customer-name.co.uk'
     $Global:Fromaddress = $Global:Fromaddress.Replace(' ' , '')
     if($Fromaddress -notmatch "@"){ Write-Warning 'Not valid email address'}
     else{Set-FsrmSetting -FromEmailAddress $Fromaddress}
    }
  while(($Fromaddress -notmatch "@") -and ($Adminaddress -notlike "q"))

}

Function Get-MappedDrives{

try
{
Import-Module GroupPolicy -ErrorAction Stop
}
catch
{
throw "Module GroupPolicy not Installed"
}
        $GPO = Get-GPO -All
 
        foreach ($Policy in $GPO){
 
                $GPOID = $Policy.Id
                $GPODom = $Policy.DomainName
                $GPODisp = $Policy.DisplayName
 
                 if (Test-Path "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences\Drives\Drives.xml")
                 {
                     [xml]$DriveXML = Get-Content "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences\Drives\Drives.xml"
 
                            foreach ( $drivemap in $DriveXML.Drives.Drive )
 
                                {New-Object PSObject -Property @{
                                    GPOName = $GPODisp
                                    DriveLetter = $drivemap.Properties.Letter + ":"
                                    DrivePath = $drivemap.Properties.Path
                                    DriveAction = $drivemap.Properties.action.Replace("U","Update").Replace("C","Create").Replace("D","Delete").Replace("R","Replace")
                                    DriveLabel = $drivemap.Properties.label
                                    DrivePersistent = $drivemap.Properties.persistent.Replace("0","False").Replace("1","True")
                                    DriveFilterGroup = $drivemap.Filters.FilterGroup.Name
                                }
                            }
                }
        }
        }

function Update-Definition {

  Write-Host ''
  Write-Host 'This will update the 1-Cryptpto File group with new definitions to detect for on the file shares.'   -ForegroundColor Green
  Write-Host ''
  Write-Host 'You must separate each definition with a comma [ , ] wildcard [ * ] can be used also'  -ForegroundColor Green
  Write-Host ''
  Write-Host 'EXAMPLE: *crypto*,*virus*,*johnycrypto*.gmail* '   -ForegroundColor Green

  Write-Host ''
  
  While($Pattern -notlike 'q'){
     $Error.Clear()

     ## STRING OF VARIABLES
     $Pattern = Read-Host 'Definitions'
  
     if ($Pattern -notlike 'q') {

    ## crazy code Tom wrote which we didn't need LOL
    ## $Pattern = $Pattern -replace ",",""","""
    ## $pattern = """$pattern"""
        
  
        ## SPLIT STRING INTO SEPRATE ITEMS WITH ,
        $Definition = $Pattern.Split(',')
        foreach ($item in $Definition) {

           $Group = Get-FsrmFileGroup "1-PreventCrypto"
           $List = $Group.IncludePattern + $Item

           ## UPDATE THE FILEGROUP WITH EACH ITEM
           Set-FsrmFileGroup -Name '1-PreventCrypto' -IncludePattern @( $List)
           
           Write-Host ''
           Write-Host 'Definition Added'  -ForegroundColor Green
           Write-Host ''

           }
      }  
      Else{}
  }
  Pause




}

function InvokeUpdate-Email{

## GET COMPUTERS WITH FSRM
$Computer = Get-ADComputer -Filter {OperatingSystem -Like "Windows *server*"} -Properties Name |
    Select-Object -ExpandProperty Name |
    Where-Object { Test-Connection -ComputerName $PSItem -BufferSize 1 -Count 1 -TimeToLive 1 -ErrorAction SilentlyContinue }

$Computers = Invoke-Command $Computer -Scriptblock {Get-WindowsFeature -Name FS-Resource-Manager | where-object {$_.Installed -eq $true}}

## CREATE SESSION FOR EACH SERVER WITH FSRM
$Session = New-PSSession -ComputerName $Computers.PSComputername

## SET SMTP SERVER
    $smtp = Read-Host 'Smtp server'
    $smtp = $smtp.Replace(' ' , '')

## SET ADMIN  ADDRESS
   do{
     $Adminaddress = Read-Host 'Defualt recipient [Admin] address'

     if(($Adminaddress -notmatch "@") -or ([string]::IsNullOrWhiteSpace($Adminaddress))){ Write-Warning 'Not valid email address'}
     ## if($Adminaddress -notmatch "@"){ Write-Warning 'Not valid email address'}
     Else {$Adminaddress = $Adminaddress.Replace(' ' , '')}
        }
  while($Adminaddress -notmatch "@")

##SETS [FROM] ADDRESS
  Do{
     $Fromaddress = Read-Host 'Enter [From] email address eg:CRYPTO_ALERT@customer-name.co.uk'
     if($Fromaddress -notmatch "@"){ Write-Warning 'Not valid email address'}
     else{$Fromaddress = $Fromaddress.Replace(' ' , '')}
    }
  while($Fromaddress -notmatch "@")

### SCRIPTBLOCK DEFINED (params and all that!)
    $scriptBlock = {
        param($Script3,$Script4,$Script5)
        Set-FsrmSetting -SmtpServer $Script3
        Set-FsrmSetting -CommandNotificationLimit 2 -EmailNotificationLimit 2 -EventNotificationLimit 2
        Set-FsrmSetting -AdminEmailAddress $Script4
        Set-FsrmSetting -FromEmailAddress $Script5
        Write-Output "Settings changed on $env:COMPUTERNAME"
    }

## RUN THE SCRIPT ON EACH SESSION
    Invoke-Command -Session $Session -ScriptBlock $scriptBlock -ArgumentList $smtp, $Adminaddress, $Fromaddress
 }

Function Get-DCCommand{

        
        Do{

        $error.clear()

        $Global:DC = Read-Host 'Name of Domain Controller'

        Get-PSSession | Remove-PSSession 

        if ($DC -notlike 'q'){

                    #this imports the remote modules to the local computer, no need to run scripts on the actual $DC
            $S = New-PSSession $DC
            Import-PSSession -CommandName Get-AdComputer -Session $S

        }
        else {}
        }
        while (($Error.count -gt 0) -or ($DC -like $null))

        }

Function InvokeUpdate-Definition{


## CREATE SESSION FOR EACH SERVER WITH FSRM
$Session = New-PSSession -ComputerName $Using:Computers.PSComputername


    $Pattern = Read-Host 'Definitions'


### SCRIPTBLOCK DEFINED (params and all that!)
    $scriptBlock = {
        param($Script0)

        $Definition = $Script0.Split(',')
        foreach ($item in $Definition) {

           $Group = Get-FsrmFileGroup "1-PreventCrypto"
           $List = $Group.IncludePattern + $Item

           ## UPDATE THE FILEGROUP WITH EACH ITEM
           Set-FsrmFileGroup -Name '1-PreventCrypto' -IncludePattern @( $List)


        Write-Output "Settings changed on $env:COMPUTERNAME"
    }
    }

## RUN THE SCRIPT ON EACH SESSION
    Invoke-Command -Session $Session -ScriptBlock $scriptBlock -ArgumentList $Pattern

}

### variables are removed after each switch command - this might be bad....

## Function Run-CryptoMenu{

do
{
  Show-Menu

  $input = Read-Host 'Please make a selection'
  switch ($input)
  {
    '1' {
      ###################################
      Clear-Host

      Show-Title
      
      $SubMenu = '--------------------- Crypto-Detect Install [Local] -----------------------'
      Write-Host '--------------------- Crypto-Detect Install [Local] -----------------------' -ForegroundColor 'green'
      Write-Host ''

      ## CALL FUNCTIONS
      Install-Crypto
      Set-Email

      Clear-Host

      Show-Title
      
      Write-Host $SubMenu -ForegroundColor 'green'

      ## CALL FUNCTION
      Install-Screen
      
      Write-Host ''
      Write-Host '--------------------- Crypto-Detect Install [Complete] -----------------------' -ForegroundColor 'green'
      Write-Host ''

      Pause

      ###################################
    }
    '2' {
      Clear-Host

      Show-Title
      Write-Host '-------------------------- Mapped Drive GPOs -----------------------------' -ForegroundColor green
      Write-Host '[Q] Press Q to Quit' -ForegroundColor 'yellow'
      Write-Host ''

      do {
        
        $DC = Read-Host 'Name of Domain Controller'
        if ($DC -eq 'q') {}

        else {
          $Error.Clear()

          ## RUN GPPDRIVEMAP SCRIPT ON DC
          Invoke-Command -ComputerName $DC -ScriptBlock ${Function:Get-MappedDrives} | select drivePath, DriveLabel, DriveLetter | Sort DriveLetter | Format-Table
        }
      }
      while (($Error.Count -eq 1) -and ($DC -notlike 'q'))

      Pause
    }
    '3' {
      Clear-Host
      ########################## FSRM remote insatll ############################

      Show-Title
      Write-Host '-------------------- Crypto-Detect Install [Remote] -----------------------' -ForegroundColor Green

      Get-Remote

      if ($Remote -notlike 'q') {


        ## Dont need to copy files any more, as specify $PSScriptRoot for file locations :)

        New-Item -ItemType Directory \\$Remote\c$\CryptoDetectV1 -Force
        Copy-Item $PSScriptRoot\Crypto_filegroup.xml \\$Remote\c$\Crypto_filegroup.xml -Verbose -Force
        Copy-Item $PSScriptRoot\filescreenCrypto.xml \\$Remote\c$\filescreenCrypto.xml -Verbose -Force
        Copy-Item $PSScriptRoot\1-PreventCrypto.bat \\$Remote\c$\1-PreventCrypto.bat -Verbose

        Write-Host ''

        $Global:Choice = '3'

        ## Install FSRM via Function {Install-Crypto)}
        $RemoteInstall = Read-Host 'Install FSRM, File Screens and Protect server Shares [y] or [n] ?'
        if ($RemoteInstall -match 'yes|y')
        { Invoke-Command -ComputerName $Remote -ScriptBlock ${Function:Install-Crypto}
        
        $Global:Choice = $Null

        Remove-Item \\$Remote\c$\Crypto_filegroup.xml -Verbose -Force
        Remove-Item \\$Remote\c$\filescreenCrypto.xml -Verbose -Force
          
          ## EMAIL CONFIG FUNCTION
          Invoke-Command -ComputerName $Remote -ScriptBlock ${Function:Set-Email}

          Clear-Host
          Show-Title
          Write-Host "------------------ Crypto-Detect Install [$Remote] ----------------------" -ForegroundColor Green
          
          ## INSTALL SCREENS FUNCTION
          Invoke-Command -ComputerName $Remote -ScriptBlock ${Function:Install-Screen}
          
          Remove-Item \\$Remote\c$\1-PreventCrypto.bat -Verbose -Force

          Write-Host ''
          Write-Host '--------------------- Crypto-Detect Install [Complete] -----------------------' -ForegroundColor 'green'
          Write-Host ''
        
        
        }
      }
      else {}

      Pause


    }
    '4' {
      Clear-Host

      Show-Title
      Write-Host '------------------------ Crypto-Detect [Eamil Config]---------------------------' -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[A] Local Email Config' -ForegroundColor 'green'
      Write-Host '[B] Remote Email Config' -ForegroundColor 'green'
      Write-Host '[C] Update all FSRM Servers' -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[Q] Return to Main Menu'
      Write-Host ''

      $input3 = Read-Host 'Please make a selection'

      switch ($input3) {

        'A' {

          Set-Email
        }
        'B' {

          Get-Remote

          ## UPDATES EMAIL CONFIG ON A REMOTE PC WITH A FUNCTION
          Invoke-Command -ComputerName $Remote ${Function:Set-Email}

        }
        'C' {
        InvokeUpdate-Email

        Pause
        }

      }


    }
    '5' {
      ########### Install Screen on local server #######
      Clear-Host
      Show-Title
      Write-Host '---------------------- Protect Shared Drive [Local] ------------------------' -ForegroundColor green
      
      ## ADD FILE SCREEN TO LOCAL SERVER WITH FUNCTION
      Install-Screen

      Pause
    }
    '6' {
      Clear-Host


      Show-Title
      Write-Host '------------------ Crypto-Detect Install [Remote] -----------------------' -ForegroundColor Green
      Write-Host ''

      Get-Remote

      Clear-Host

      Show-Title
      Write-Host "------------------ Crypto-Detect Install [$Remote2] ----------------------" -ForegroundColor Green

      ## ADD FILE SCREEN ON REMOTE SERVER WITH A FUNCTION
      if ($Remote -notlike 'q') {Invoke-Command -ComputerName $Remote -ScriptBlock ${Function:Install-Screen}
   
      Pause}

    }
    '7' {
      Clear-Host

      Show-Title
      Write-Host '------------------------- Crypto-Detect Test ------------------------------' -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[A] Local Test' -ForegroundColor 'green'
      Write-Host '[B] Remote Test' -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[Q] Return to Main Menu'
      Write-Host ''

      $input2 = Read-Host 'Please make a selection'
      switch ($input2) {

        'A' {
          Clear-Host
          Show-Title
          Write-Host '---------------------- Crypto-Detect Test [Local]--------------------------' -ForegroundColor 'green'
          Write-Host ''
          
          ## TEST CRYPTO DETECT ON LOCAL SERVER WITH FUNCTION
          Test-Crypto

          Pause

        }
        'B' {
          Clear-Host
          Show-Title
          Write-Host '------------------- Crypto-Detect Test [Remote]-----------------------' -ForegroundColor 'green'
          Write-Host ''

          Get-Remote

          Clear-Host
          Show-Title
          Write-Host "--------------------- Crypto-Detect Test [$Remote]--------------------------" -ForegroundColor 'green'
          Write-Host ''

          ## TEST CRYPTO DETECT ON REMOTE SERVER WITH FUNCTION
          if ($Remote -notlike 'q'){Invoke-Command -ComputerName $Remote -ScriptBlock ${Function:Test-Crypto}

          Pause}

        }
        'q' {


        }


      }

    }
    '8' {
      Clear-Host

      Show-Title
      Write-Host '------------------------ Crypto-Detect Definitions ------------------------' -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[A] Update Definitions on Local Server' -ForegroundColor 'green'
      Write-Host '[B] Update Definitions on Remote Server' -ForegroundColor 'green'
      Write-Host '[C] Update all FSRM servers'    -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[Q] Return to Main Menu'
      Write-Host ''
      $input3 = Read-Host 'Please make a selection'
      switch ($input3) {

        'A' {
          
          ##UPDATE FILE GROUP DEFINITION ON LOCAL SERVER WITH FUNCTION
          Update-Definition
        }
        'B' {

          Clear-Host

          Show-Title
          Write-Host '---------------------- Crypto-Detect Definitions [Remote]------------------' -ForegroundColor 'green'
          Write-Host ''

          Get-Remote

          ##UPDATE FILE GROUP DEFINITION ON REMOTE SERVER WITH FUNCTION
          Invoke-Command -ComputerName $Remote ${Function:Update-Definition}

        }
        'C' {

        Write-host ''
        Write-Host 'Get Servers with FSRM Install' -ForegroundColor blue
        Write-host ''

        
        Get-DCCommand
        $Error.Clear()

        If (($DC -notlike 'q') -and ($DC -notlike $Null)){

          $Error.Clear()

        $ComputerList = (Get-ADComputer -Filter {OperatingSystem -Like "Windows *server*"}).Name|
        Where-Object { Test-Connection -ComputerName $PSItem -BufferSize 1 -Count 1 -TimeToLive 80 -ErrorAction SilentlyContinue }

        

        $Results=Invoke-Command $ComputerList -Scriptblock {Get-WindowsFeature -Name FS-Resource-Manager | where-object {$_.Installed -eq $true}}

        Clear
        Show-Title
        Write-Host '---------------------- Crypto-Detect Definitions [ALL]---------------------' -ForegroundColor 'green'

        Write-Host ''
        Write-Host 'Update Definitions on all servers with FSRM Install' -ForegroundColor Blue


          Write-Host ''
  Write-Host 'This will update the 1-Cryptpto File group with new definitions to detect for on the file shares.'   -ForegroundColor Green
  Write-Host ''
  Write-Host 'You must separate each definition with a comma [ , ] wildcard [ * ] can be used also'  -ForegroundColor Green
  Write-Host ''
  Write-Host 'EXAMPLE: *crypto*,*virus*,*johnycrypto*.gmail* '   -ForegroundColor Green

  Write-Host ''


        
        $Pattern = Read-Host 'Definitions'
       
        foreach($computer in $Results){
        $Session = New-PSSession -ComputerName $computer.PSComputername

        Invoke-Command -Session $Session -ScriptBlock `
        {
            param($Script0)

            $Definition = $Script0.Split(',')
            foreach ($item in $Definition) {

               $Group = Get-FsrmFileGroup "1-PreventCrypto"
               $List = $Group.IncludePattern + $Item

               ## UPDATE THE FILEGROUP WITH EACH ITEM
               Set-FsrmFileGroup -Name '1-PreventCrypto' -IncludePattern @( $List)

                Write-Output "Settings changed on $env:COMPUTERNAME"
                Write-Host ''
            }
        } -ArgumentList $Pattern

        #don't forget to remove the sessions when you're done!
        


  }  
  

           $Session|Remove-PSSession   
           Remove-PSSession -ComputerName $DC
        }



      Pause
        }

        'q'{}
      }
      
       


    }

    '9' {
      Clear-Host

      get-help Install-Crypto -Showwindow
      
      ##Get-Help Install-Crypto -Full | Out-File $PSScriptRoot\Crypto-DetectHelp.txt
      
      ## OPENS HELP IN NOTEPAD
      ##Invoke-Item -Path $PSScriptRoot\Crypto-DetectHelp.txt


    }
    'q' {

      ## QUITS BACK TO C:\ PROMPT
      return
    }

  }

}
until ($input -eq 'q')



##  }
## function (Run-CryptoMenu) end brackets above