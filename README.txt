######################################
#            PvPGN Firewall          #
######################################

Hi!
This is a very simple firewall to protect your D2GS.exe process.
So, here are some instructions and things to keep in mind.

######################################
#           PRE-REQUISITES           #
######################################

Install Python 3.11 or above, then this libraries:
- pydivert
- psutil

For example in Windows, install Python, remember in the installation set "Use Admin privilegies", and "Add Python PATH".
Then in a CMD with admin privilegies type:

pip install pydivert
pip install psutil

Then, just execute like admin "Start Firewall.bat", Done!

######################################
#             SETTINGS               #
######################################

In the --- config.json --- you set the parameters to adjust the firewall here we have the important variables:

  "BAN_DURATION" = Time in minutes a IP that send flood packages will be temporary banned.
  "MAX_TEMP_BANS" = The max allowed temporal bans a IP can have before get a permanent ban.
  "TIME_FOR_MAX_PACKETS" = Time in seconds to not consider flood packets as malicious.
  "MAX_PACKETS_THRESHOLD" = It's the number of flood packets allowed in the previously set time.
   For example: If TIME_FOR_MAX_PACKETS set to 10, and MAX_PACKETS_THRESHOLD to 12
   will allow 12 packets in a range of 10 seconds, this is only for Flood packages.
  
  "BLOCKED_PACKET_THRESHOLD" = It's the max number of malicious packets to count before permanent ban the IP.
  "BLOCKED_PORT" = Default D2GS Port, never change.
  "LOGIN_PORT" = PvPGN Login port, usually this never change, this disable the login for any permanent ban IP.
  "FIREWALL_RESTART" = Set True or False to restart the firewall after several hours to clear memory.
  "FIREWALL_RESTART_HOURS" = Time in hours to restart the firewall, for example 24 hs.
  "PROCESS_MONITOR" = Monitor the D2GS, True or False. This restart the D2GS.exe if crash for some reason.
  "PROCESS_NAME" = The D2GS.exe name to monitor, usually this never change.
  "PROCESS_PATH" = The complete folder path of the D2GS remember put doble \\.

######################################
#       PAYLOADS (Hex Codes)         #
######################################
  
You can set the "payloads" this are hex codes to stop, you have three files:

payloads.json = This are malicious payloads never go to D2GS process, always drop.
payloads_login.json = This are payloads that make a temporary ban like RedVex cheat, in login.
payloads_flood.json = These are payloads that pass, but in excessive quantity are harmful.

In all cases you have two ways to set the payloads inside this files:

starting_with = If the payload start with that code, it's detected.
fixed = It's a complete sstructure of code, will be detected only if the packet arrive it's exactly like that. 

Check the EXAMPLE_payloads.json for more information.

By default you will have inside:

payloads.json = The most common attack hex code 
payloads_login.json = The hex code to disable RedVex cheat login.
payloads_flood.json = The overhead chat, to avoid flood.

NOTE: If you have only one code for example in starting_with and you don't have any in fixed code, put the same
in the two places, like in the default: payloads_flood.json

######################################
#       PERMANENT BANNED IPs         #
######################################

This go to the file --- permaban_ips.json --- you can remove it from there editing the file, for example:

{"172.21.41.6": 1, "186.71.42.3": 1}

You want to remove the 172.21.41.6, you will end with something like this:

{"186.71.42.3": 1}

##################################################################################################################

That's all - Special thanks to MayhemARG to build the bases of the firewall, and the people in forums.pvpgn.pro
-- GecKoTDF