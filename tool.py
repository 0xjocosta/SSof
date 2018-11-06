import sys
import json
from pwn import *

#Static Names
CONST_N_INSTRUCTIONS = "Ninstructions"
CONST_VARIABLES = "variables"
CONST_INSTRUCTIONS = "instructions"

#Dangerous functions
dangerousFunctions = ["gets", "strcpy", "strcat", "sprintf", "scanf", "fscanf", "fgets", "strncpy", "strncat", "snprintf", "read"]

#Assembly instructions
assemblyInstructions = {"basic": ["ret", "leave", "nop", "push", "pop", "call", "mov", "lea", "sub", "add"], "advanced": ["cmp", "test", "je", "jmp", "jne"]}

if(len(sys.argv) < 2):
    print "No program received!"
    exit()

with open(str(sys.argv[1])) as json_data:
    jsonProgram = json.load(json_data)

for function in jsonProgram:
    checkFunction(jsonProgram[function])
    

def checkFunction(function):
    return    
