
The `cumulus-ztp` file is a python script that is designed to be used as a Zero Touch Provisioning script with Cumulus Linux 3.7.2 or later and will automatically provsion a switch for the Cumulus Hyperconverged Service (HCS). 

To use this ZTP script, perform the following:
1. Copy `cumulus-ztp` and `ztp_config.txt` to a USB stick
2. Edit `ztp_config.txt` and input information about your Nutanix cluster
3. Without Cumulus on a Stick, edit `cumulus-ztp` and replace `LICENSE_KEY_GOES_HERE` with your license string
4. Insert the USB stick into a switch running Cumulus Linux and the ZTP process will trigger automatically.
5. Verify that ZTP completed with `ztp -s` and by viewing `/var/log/syslog` and looking for `ZTP` lines.
