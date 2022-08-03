# AutoSSH
AutoSSH is a Reverse Shell Listener made using PwnTools which allows the user to automatically check whether SSH persistence is possible, if so it will place the ssh public key within the code into the authorized_keys file within the user's ".ssh/" directory. Additionally it performs some simple parsing of the `/etc/ssh/sshd_config` file to check whether only certain users can ssh into the machine via the use of the SSHD `AllowUsers` keyword.

## Running AutoSSH
```
python3 AutoSSH.py
```
Note : if term.term_mode is not enabled some of the output may look weird due to the way the pwnlib logging system and underlying logging module functions

### Notes / Potential Issues
1. The Possibility for root SSH access is not checked 
2. More advanced SSHD detection should be added
