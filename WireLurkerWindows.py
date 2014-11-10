'''
Created on Nov 9, 2014

@author: Kaustubh Sant
@copyright: Copyright (c) 2014 Kaustubh Sant
@version: 1.0
'''

"""Detecting the WireLurker malware family on Windows."""

import os

Block_size = 102400 # 100kb chunk of file read at a time
infectedfiles=[]

def scanfile(inFile):
    eocdcount=0; # \x50\x4b\x05\x06
    str1exists = False # Payload/apps.app/sfbase.dylib
    str2exists= False # Payload/apps.app/sfbase.plist"
    with open(inFile,'rb') as fin:
            blockbytes = fin.read(Block_size)
            while(blockbytes):
                if("\x50\x4B\x05\x06" in blockbytes):
                    eocdcount = eocdcount + 1
                if("Payload/apps.app/sfbase.dylib" in blockbytes):
                    str1exists = True
                if("Payload/apps.app/sfbase.plist" in blockbytes):
                    str2exists = True
                if(eocdcount == 4 and str1exists==True and str2exists==True):
                    infectedfiles.append(inFile)
                    break
                blockbytes = fin.read(Block_size)
    
    
def scandrive(drivepath):
    print("Scanning files in " + drivepath.split(":")[0] + " drive ...")
    for root,dirs,files in os.walk(drivepath):
        for name in files:
            if(name.split(".")[-1]=="exe"): #scan only executable files
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
    
def main():
    print("*** WireLurkerDetector ***\n")
    Drivepath = "C:\\"
    scandrive(Drivepath)
    
    
if __name__ == '__main__' :
    main()