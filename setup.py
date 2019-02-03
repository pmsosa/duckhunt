from distutils.core import setup
import py2exe, sys, os
#This to change the script to an exe edit the variables inside the duckhunt-configurable.py file then run this script
sys.argv.append('py2exe')

setup(

    name = 'duckhunt',
    description = 'duckhunt-',

    options = {'py2exe': {'bundle_files': 1, 'compressed': True}},
    windows = [{'script': "duckhunt-configurable.py"}],
    zipfile = None,
)


