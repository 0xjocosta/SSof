import sys
import json
from pwn import *

if(len(sys.argv) < 2):
    print "No program received!"
    exit()

jsonProgram = str(sys.argv[1])
with open(jsonProgram) as json_data:
    program = json.load(json_data)
    
