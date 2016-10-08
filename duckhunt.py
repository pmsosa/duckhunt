######################################################
#                   DuckHunter                       #
#                 Pedro M. Sosa                      #
# Tool to prevent getting attacked by a rubberducky! #
######################################################

from ctypes import *
import pythoncom
import pyHook 
import win32clipboard
import win32ui
import os
import shutil
from time import gmtime, strftime
from sys import stdout


##### NOTES #####
#
# 1. Undestanding Password Protection Policy:
#   - Password Protection  ON : When a rubber ducky attack is detected, lock down any further keypresses until the correct password is entered.
#   - Without Password Protection: When a rubber ducky attack is detected, it will lock down any further keypresses until the time spacing between keys goes above the threshold.
#
# 2. How To Use
#   - Modify the user configurable vars below. (particularly pwdprotect and password)
#   - Turn the program into a .pyw to run it as windowless script.
#   - (Opt) Use py2exe to build an .exe
#
#################




### USER CONFIGURABLE ###
threshold   = 30        # Speed Threshold between keystrokes (Default: ~30 Miliseconds) | Anything faster than this is suspicious.
size        = 25        # Size of Vector that holds the history of keystroke speeds (Default: 25 Keystokes)
pwdprotect  = True      # Turn Password Protection On/Off
password    = "QUACK"   # The password you are going to use to recover keyboard control
#########################


pcounter  = 0           # Password Counter (If using password)
speed     = 0           # Speed
prevTime  = -1          # Previous Keypress Timestamp
i         = 0           # Vector Timeslot
intrusion = False       # Boolean Flag to be raised in case of intrusion detection
vector    = [threshold+1] * size #Array for keeping track of average speeds across the last n keypresses




#This is triggered every time a key is pressed
def KeyStroke(event):

    global threshold, pwdprotect, password, pcounter
    global speed, prevTime, i, vector, intrusion


    #If an intrusion was detected and we are password protecting
    #Then lockdown any keystroke and until password is entered
    if (pwdprotect & intrusion):    
        print event.Key;
        if (password[pcounter] == chr(event.Ascii)):
            pcounter += 1;
            if (pcounter == len(password)):
                print "Correct Password -- Unlocking!"
                intrusion = False
                pcounter = 0
        else:
            pcounter = 0

        return False


    #Initial Condition
    if (prevTime == -1):
        prevTime = event.Time;
        return True


    if (i >= len(vector)): i = 0;

    #TypeSpeed = NewKeyTime - OldKeyTime
    vector[i] = event.Time - prevTime
    print event.Time,"-",prevTime,"=",vector[i]
    prevTime = event.Time
    speed = sum(vector) / float(len(vector))
    i=i+1

    print "\rAverage Speed:",speed

    #Intrusion detected
    if (speed < threshold):
        print "Quack! Quack! -- Time to go Duckhunting!"
        intrusion = True; 
        if (pwdprotect):
            win32ui.MessageBox("Someone might be trying to inject keystrokes into your computer.\nPlease check your ports or any strange programs running.\nEnter your Password to unlock keyboard.", "KeyInjection Detected",4096) # MB_SYSTEMMODAL = 4096 -- Always on top.
        return False


    # pass execution to next hook registered 
    return True

# create and register a hook manager 
kl         = pyHook.HookManager()
kl.KeyDown = KeyStroke

# register the hook and execute forever
kl.HookKeyboard()
pythoncom.PumpMessages()

