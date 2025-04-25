#!/bin/bash

# This script launches ryu-manager with optional Flow Manager support.
# If flowmanager.py exists, it will be loaded automatically.

# Check if Flow Manager is available at the specified path.
FLOWMANAGER=$([ -f "./src/tools/flowmanager/flowmanager.py" ] &&
    echo "./src/tools/flowmanager/flowmanager.py")

# Launch ryu-manager with the main application.
# The $FLOWMANAGER variable will be included only if the file exists.
# --observe-links enables topology discovery.
# --default-log-level 30 sets the logging level to WARNING. Prevents logs spamming.
ryu-manager --default-log-level 30 --observe-links ./src/controller/main.py $FLOWMANAGER
