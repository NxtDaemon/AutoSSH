## Pseudocode 
- Generate and store credentials to upload
- Have the ability to open a netcat listening session and connect back to it
  - run enumeration commands to display to user
  - ID
  - Whoami
  - Uname -a
- have a shell script that you can pull to the machine and run it 
- be able to run it

## Script to add key to hosts 
```
#!/bin/bash
key="content here"

echo "$key" >> ~/.ssh/known_hosts
if [[ $? -ne 0 ]]; then
echo "Failed"
else
echo "completed"
fi
```
```
./s.sh 2>/dev/null
```
