#!/usr/bin/python3
#Mark Nesbitt
#20171003
#padding attack info: https://robertheaton.com/2013/07/29/padding-oracle-attack/ 

#This assumes that the plaintext is 32 bytes therefore the ciphertext is 48 bytes due to 16 bytes of padding.  This was given in the assignment
import socket
import re 
import sys
import os
#import subprocess

def mypaddingCorrect(ciphertext):
    f = open("tempjunk", 'wb')
    f.write(ciphertext)
    f.close()
    status = 1
    oscommand = "openssl aes-128-cbc -d -in tempjunk -K 1239ddf -iv 85D4856F1735F596B7266C93A4836C8C"
    #command = ["openssl", "aes-128-cbc", "-d", "-in", ciphertext, "-K", "1239ddf", "-iv", "85D4856F1735F596B7266C93A4836C8C"]
    try:
        #status = subprocess.call(command)
        status = os.system(oscommand)
    except:
        pass
    if status == 0:
        return True
    else:
        return False

def paddingCorrect(ciphertext):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("172.19.5.133",5000))
    s.sendall(ciphertext)
    reply = s.recv(1000)
    match = re.search("Padding error",str(reply))
    if match:
        return False
    else:
        #print("No padding error with ciphertext:\n"+str(ciphertext))
        return True

def findByte(xorblock, tgtblock, byteindex): #assumes that byteindex+1:endofblock is padded properly byteindex+1, i.e. that sending the ciphertext with the given xorblock and tgtblock gets a "yes" from the oracle. Everything is bytes, in and out
    #print("Our bytes are:\n")
    #print(tgtblock[byteindex]) #blocks come in as bytes, this should make them decimals
    #print(tgtblock[byteindex:byteindex+1], bytes((tgtblock[byteindex],)))
    #print(xorblock[byteindex])
    #print(xorblock[byteindex:byteindex+1], bytes((xorblock[byteindex],)))
    padbytesdec = 16 - byteindex
    #print(padbytesdec)
    extrapadding = b''
    for i in range(padbytesdec-1):
        tempdec = xorblock[15-i]^(padbytesdec-1)^padbytesdec
        extrapadding = bytes((tempdec,))+extrapadding
    for ptguessdec in range(256): 
        testbytedec = xorblock[byteindex]^padbytesdec^ptguessdec#NEXT LINE IS THE PROBLEM-- need to increment the padding not just replicate it
        modxorblock = xorblock[:byteindex]+bytes((testbytedec,))+extrapadding#The testbytedec is correct but you're not converting it to hex properly Try +bytes((subbytedec,))  old code +chr(subbytedec).encode()+
        #print(xorblock+tgtblock)
        #print(modxorblock+tgtblock)
        #print("\n\nOracleResults (orgct, modct)")
        #print(paddingCorrect(xorblock+tgtblock))
        #print(paddingCorrect(modxorblock+tgtblock))
        #print("\n\n")
        if paddingCorrect(modxorblock+tgtblock):
            #print("PT byte found "+str(ptguessdec)+" (dec) ",bytes((ptguessdec,)))#str(chr(ptguessdec).encode())+" (byte)")
            #print(bytes((ptguessdec,)))
            return modxorblock, bytes((ptguessdec,))
        else:
            #print("Incorrect guess: "+str(ptguessdec)+" (dec) "+str(chr(ptguessdec).encode())+" (byte)")
            pass
    sys.exit(1)

def findBlock(iv, ciphertext, blockindex):
    tgtpt=b''
    if blockindex == 0:
        tgtblock = ciphertext[:16]
        xorblock = iv
    else:
        tgtblock = ciphertext[(16*blockindex):16*(blockindex+1)]
        xorblock = ciphertext[16*(blockindex-1):(16*blockindex)] 
    modxorblock = xorblock 
    for i in range(15,-1,-1):#(15,-1,-1):
        modxorblock, latestbyte = findByte(modxorblock, tgtblock, i)#, xorblock[i], i)   #xorblock -- why does it cast to str without slicing?
        tgtpt = latestbyte + tgtpt
        #print("\n\nUPDATED TARGET PLAINTEXT:\n\n") 
        #print(tgtpt)
    return tgtpt 

def findPlaintext(iv, ciphertext):
    pt=b''
    ctlength = 32 #2 blocks of ct, given for this assignment, needs to be variable, therefore next line needs error checking
    blocks = ctlength // 16
    for i in range(blocks):
        pt+=findBlock(iv, ciphertext, i)
    return pt

def main():
    f = open('cipher.txt', 'rb')
    rawct = f.read()
    f.close()
    relevantct = rawct[:32]
    g = open('iv.txt', 'rb')
    tempiv = g.read().splitlines()
    g.close()
    iv = tempiv[0]
    iv = b'\x85\xd4\x85\x6f\x17\x35\xf5\x96\xb7\x26\x6c\x93\xa4\x83\x6c\x8c' #Hard coded because even after all of this I suck at handling bytes objects in python

    #print(relevantct[-17])
    #print(mypaddingCorrect(rawct))
    #findByte(relevantct[:16], relevantct[16:], 15)
    #tempjunk = findBlock(iv, relevantct,0)
    #print("\n\nOUTPUT of findBlock(iv,relevantct,1)\n\n")
    #print(tempjunk)
    pt = findPlaintext(iv, relevantct)
    #print("\n\n\nPLAINTEXT:")
    print(pt)

if __name__ == '__main__':
    main()
