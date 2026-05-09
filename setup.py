#!/usr/bin/env python
"""
Setup script for building the DuckHunter executable using py2exe.

Before building, ensure that any configurable variables in duckhunt-configurable.py
are properly set. This script packages duckhunt-configurable.py into a single,
compressed executable. Optionally, if an icon file named "app.ico" is present,
it will be used for the executable's icon.

Author: Pedro M. Sosa
Version: 1.0
"""

from distutils.core import setup
import py2exe
import sys
import os

# Ensure the py2exe command is added to sys.argv if not already provided.
if 'py2exe' not in sys.argv:
    sys.argv.append('py2exe')

# ---------------------------------------------------------------------------
# Py2exe Options:
# - bundle_files: 1  --> Bundle everything into a single executable.
# - compressed: True  --> Compress the library archive.
# - optimize: 2  --> Use the maximum optimization level.
# - dll_excludes: Avoid bundling specific DLLs.
# - dist_dir: Directory where the output executable will be placed.
# ---------------------------------------------------------------------------
py2exe_options = {
    'py2exe': {
        'bundle_files': 1,
        'compressed': True,
        'optimize': 2,
        'includes': [],       # List additional modules to include if necessary.
        'excludes': [],       # List modules to exclude.
        'dll_excludes': ['MSVCP90.dll'],  # Common exclusion to avoid potential issues.
        'dist_dir': 'dist',
    }
}

# ---------------------------------------------------------------------------
# Metadata and executable configuration.
# Modify these values as needed.
# ---------------------------------------------------------------------------
metadata = {
    'name': 'duckhunt',
    'version': '1.0',
    'description': 'DuckHunter - Tool to prevent getting attacked by a rubberducky!',
    'author': 'Pedro M. Sosa',
    'script': 'duckhunt-configurable.py',  # Main script to convert.
    # If your script is a GUI app, replace 'console' with 'windows'
    'exe_type': 'windows',  # Change to 'console' if no GUI is used.
    'icon': 'app.ico'       # Optional icon file; ensure this file exists in the same directory.
}

# Check if an icon file exists.
icon_resources = []
if os.path.exists(metadata['icon']):
    icon_resources = [(1, metadata['icon'])]

# ---------------------------------------------------------------------------
# Setup Configuration:
# - For windowed applications, we use the "windows" keyword.
# - For console applications, replace "windows" with "console" in the setup call.
# ---------------------------------------------------------------------------
setup(
    name=metadata['name'],
    version=metadata['version'],
    description=metadata['description'],
    author=metadata['author'],
    options=py2exe_options,
    # Use "windows" for a GUI app; if your app is console-based, change this to "console"
    windows=[{'script': metadata['script'], 'icon_resources': icon_resources}] if icon_resources else [{'script': metadata['script']}],
    zipfile=None,  # Bundle everything into the exe (no separate zip file)
)
