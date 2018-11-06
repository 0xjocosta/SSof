import sys
import json
from pwn import *

#Static Names
CONST_N_INSTRUCTIONS = "Ninstructions"
CONST_VARIABLES = "variables"
CONST_INSTRUCTIONS = "instructions"
CONST_OPERATION = "op"
CONST_CALL_OPERATION = "call"

#Dangerous functions
dangerousFunctions = ["fgets", "strcpy", "strcat", "sprintf", "fscanf", "scanf", "gets", "strncpy", "strncat", "snprintf", "read"]

#Assembly instructions
assemblyInstructions = {"basic": ["ret", "leave", "nop", "push", "pop", "call", "mov", "lea", "sub", "add"], "advanced": ["cmp", "test", "je", "jmp", "jne"]}


def checkInstruction(instruction):
    if (instruction[CONST_OPERATION] == CONST_CALL_OPERATION):
        functionName = str(instruction["args"]["fnname"])
        for func in dangerousFunctions:
            if func in functionName:
                print func
                return
    return

def checkFunction(function):
    variables = function[CONST_VARIABLES]
    instructions = function[CONST_INSTRUCTIONS]
    for instruction in instructions:
        checkInstruction(instruction)
    return


if(len(sys.argv) < 2):
    print "No program received!"
    exit()

with open(str(sys.argv[1])) as json_data:
    jsonProgram = json.load(json_data)

for function in jsonProgram:
    checkFunction(jsonProgram[function])

