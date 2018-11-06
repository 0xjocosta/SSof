import sys
import json

#Static Names
CONST_N_INSTRUCTIONS = "Ninstructions"
CONST_VARIABLES = "variables"
CONST_INSTRUCTIONS = "instructions"
CONST_OPERATION = "op"
CONST_CALL_OPERATION = "call"
CONST_ARGS = "args"
CONST_FNNAME = "fnname"
CONST_DEST = "dest"
CONST_VALUE = "value"
CONST_ADD = "add"
CONST_SUB = "sub"


#Dangerous functions
dangerousFunctions = ["<fgets@plt>", "<strcpy@plt>", "<strcat@plt>", "<sprintf@plt>", "<fscanf@plt>", "<scanf@plt>", "<gets@plt>", "<strncpy@plt>", "<strncat@plt>", "<snprintf@plt>", "<read@plt>"]

#Assembly instructions
assemblyInstructions = {"basic": ["mov", "lea", "sub", "add"], "advanced": ["cmp", "test", "je", "jmp", "jne"]}
registerOperations = {"sub": "-", "add": "+"}


#Registers
registers = {"rax": "", "rbx": "", "rcx": "", "rdx": "", "rdi": "", "rsi": "", "r8": "", "r9": "", "r10": "", "r11": "", "r12": "", "r13": "", "r14": "", "r15": "", "rbp": "", "rsp": "", "rip": ""}
registersOfFunctions = {}


def doRegisterOperation(instruction, nameFunction):
    operation = instruction[CONST_OPERATION]
    dest = instruction[CONST_ARGS][CONST_DEST]
    value = instruction[CONST_ARGS][CONST_VALUE]
    print instruction
    if value in registersOfFunctions[nameFunction]:
        value = registersOfFunctions[nameFunction][value]
        
    if operation in registerOperations:
        registersOfFunctions[nameFunction][dest] += registerOperations[operation] + value
    else:
        registersOfFunctions[nameFunction][dest] = value

    for register in registersOfFunctions[nameFunction]:
        if dest == registersOfFunctions[nameFunction][register]:
            registersOfFunctions[nameFunction][register] = registersOfFunctions[nameFunction][dest]

def checkOperationCall(instruction, nameFunction):
    functionName = instruction[CONST_ARGS][CONST_FNNAME]
    if functionName in dangerousFunctions:
        print functionName

def checkFunction(function, nameFunction):
    variables = function[CONST_VARIABLES]
    instructions = function[CONST_INSTRUCTIONS]

    for instruction in instructions:
        operation = instruction[CONST_OPERATION]
        
        #verifying call function
        if operation == CONST_CALL_OPERATION:
            checkOperationCall(instruction, nameFunction)
            return

        if operation in assemblyInstructions["basic"]:
            doRegisterOperation(instruction, nameFunction)
    return


#Main 
if(len(sys.argv) < 2):
    print "No program received!"
    exit()

with open(str(sys.argv[1])) as json_data:
    jsonProgram = json.load(json_data)

for function in jsonProgram:
    registersOfFunctions[function] = registers
    checkFunction(jsonProgram[function], function)
    print registersOfFunctions[function]

