<h1>DuckHunter</h1>
<h3>Prevent RubberDucky (or other keystroke injection) attacks</h3>
<hr>

**Post-Mortem for this program soon to be posted on my [blog](http://www.konukoii.com/blog)**

<h3>Intro</h3>
[Rubberduckies](https://hakshop.myshopify.com/products/usb-rubber-ducky-deluxe) are small usb devices that pretend to be usb keyboards and can type on their own at very high speeds. Because most -if not all- OS trust keyboards automatically, it is hard to protect oneself from these attacks.

**DuckHunt** is a small efficient script that acts as a daemon consistently monitoring your keyboard usage (right now, only speed is monitored) that can catch and prevent a rubber ducky attack.

<h3>Requirements</h3>
 
- [PyWin32](http://starship.python.net/~skippy/win32/Downloads.html)
- [PyHook](https://sourceforge.net/projects/pyhook/)
- [Py2Exe](http://py2exe.org/)


<h3>Setup</h3>

- Step 1. Customize duckhunt.py variables to your desire
 - You can customize the password, speed threshold, enable/disable password protection, etc.

- Step 2. Turn the duckhunt**.py** to a duckhunt**.pyw** so that the console doesn't show up when you run the program

- Step 3. (opt) Use Py2Exe to create an executable.

- Step 4. Run the program. You are now protected from RubberDuckies!

<h3>Current Features</h3>
- Basic Ducky Protection: If a rubber ducky is detected, all keystrokes deemed to be from the ducky will be ignored.
- Password Protection : If enabled, once a rubber ducky attack is detected, any and all future keystrokes will be ignored until a (specified) password is entered.

<h3>TODO</h3>
- More monitoring features: 
 - Monitor the windows where you type (eg. cmdline, regedit, run)
 - Look for certain patterns (eg. "GUI D, GUI R, cmd, ENTER")
 - specific commands (eg. powershell)
- Read from .conf file
 
 <h1>Happy Hunting!</h1>
![Duck Hunt](http://konukoii.com/blog/wp-content/uploads/2016/10/duck-hunt.jpg)
