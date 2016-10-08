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
import imp
duckhunt = imp.load_source('duckhunt', 'duckhunt.conf')

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





threshold  = duckhunt.threshold   # Speed Threshold
size       = duckhunt.size        # Size of history array
pwdprotect = duckhunt.pwdprotect  # Enable/Disable Password Protection Feature
password   = duckhunt.password    # Password used in Password Protection mode
pcounter   = 0                    # Password Counter (If using password)
speed      = 0                    # Current Average Keystroke Speed
prevTime   = -1                   # Previous Keypress Timestamp
i          = 0                    # History Array Timeslot
intrusion  = False                # Boolean Flag to be raised in case of intrusion detection
history    = [threshold+1] * size #Array for keeping track of average speeds across the last n keypresses




#This is triggered every time a key is pressed
def KeyStroke(event):

    global threshold, pwdprotect, password, pcounter
    global speed, prevTime, i, history, intrusion


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


    if (i >= len(history)): i = 0;

    #TypeSpeed = NewKeyTime - OldKeyTime
    history[i] = event.Time - prevTime
    print event.Time,"-",prevTime,"=",history[i]
    prevTime = event.Time
    speed = sum(history) / float(len(history))
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

