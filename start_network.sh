#!/bin/bash

# This script starts Mininet with the custom topology specified. The controller flag enables the
# use of an external controller: Ryu.

mn --custom ./src/network/main.py --topo SDNTestbed --controller=remote
