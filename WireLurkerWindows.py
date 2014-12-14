'''
Created on Nov 9, 2014

@author: Kaustubh Sant
@copyright: Copyright (c) 2014 Kaustubh Sant
@version: 2.0

'''
"""Detecting the WireLurker malware family on Windows."""

import os
import string
from ctypes import *

Block_size = 102400 # 100kb chunk of file read at a time
infectedfiles=[]

def scanfile(inFile):
    eocdcount=0; # \x50\x4b\x05\x06
    str1exists = False # Payload/apps.app/sfbase.dylib
    str2exists= False # Payload/apps.app/sfbase.plist"
    try:
        with open(inFile,'rb') as fin:
                if(fin.read(2)== "MZ"):
                    fin.seek(-50,2)
                    blockbytes = fin.read(50)
                    if("\x50\x4B\x05\x06" not in blockbytes): ## to improve performance skip files where \x50\x4b\x05\x06 not present in last 50 bytes
                        return
                    fin.seek(0,0)
                    blockbytes = fin.read(Block_size)
                    data=""
                    while(blockbytes):
                        startpos = fin.tell()
                        if("\x50" in blockbytes):
                            for i in range(0,len(blockbytes)):
                                if(blockbytes[i]=="\x50"):
                                    jpos = i-len(blockbytes)
                                    fin.seek(jpos,1)
                                    data = fin.read(50)
                                    if(data.startswith("\x50\x4B\x05\x06")):
                                        eocdcount = eocdcount + 1
                                    if("Payload/apps.app/sfbase.dylib" in data):
                                        str1exists = True
                                    if("Payload/apps.app/sfbase.plist" in data):
                                        str2exists = True
                                    fin.seek(startpos,0)
                        if(eocdcount == 4 and str1exists==True and str2exists==True):
                            infectedfiles.append(inFile)
                            break
                        fin.seek(startpos,0)
                        blockbytes = fin.read(Block_size)                    
    except:
        pass
    
    
def scandrive(drivepath):
    print("Scanning files in " + drivepath + " drive ...")
    drivepath = drivepath + ":\\"
    
    for root,dirs,files in os.walk(drivepath):
        for name in files:
            scanfile(os.path.join(root,name))
            
    if(not infectedfiles):
        print("Nothing found")
        return 0
    else:
        for filenames in infectedfiles :
            print(filenames)
        print "[!] WARNING: Your system is highly suspicious of being infected by the WireLurker.\n" \
              "[!] You may need to delete all malicious or suspicious files above.\n" 
        return 1

def get_drives():
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.uppercase:
        if bitmask & 1:
            drives.append(letter)
        bitmask >>= 1

    return drives
    
def main():
    print("*** WireLurkerDetector ***\n")
    drives = get_drives()
    for drivepath in drives:
        scandrive(drivepath)
    
if __name__ == '__main__' :
    main()
