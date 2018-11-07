import sys
import json

#Static Names
CONST_N_INSTRUCTIONS = "Ninstructions"
CONST_VARIABLES = "variables"
CONST_INSTRUCTIONS = "instructions"
CONST_BASIC = "basic" 
CONST_OPERATION = "op"
CONST_CALL_OPERATION = "call"
CONST_ARGS = "args"
CONST_FNNAME = "fnname"
CONST_DEST = "dest"
CONST_VALUE = "value"
CONST_ADD = "add"
CONST_SUB = "sub"

CONST_ESI = "esi"
CONST_ADDRESS = "address"
CONST_BYTES = "bytes"

#Dangerous functions
dangerousFunctions = ["<fgets@plt>", "<strcpy@plt>", "<strcat@plt>", "<sprintf@plt>", "<fscanf@plt>", "<scanf@plt>", "<gets@plt>", "<strncpy@plt>", "<strncat@plt>", "<snprintf@plt>", "<read@plt>"]

#Assembly instructions
assemblyInstructions = {"basic": ["mov", "lea", "sub", "add"], "advanced": ["cmp", "test", "je", "jmp", "jne"]}
registerOperations = {"sub": "-", "add": "+"}

#Registers
registers = {"rax": "", "rbx": "", "rcx": "", "rdx": "", "rdi": "", "rsi": "", "r8": "", "r9": "", "r10": "", "r11": "", "r12": "", "r13": "", "r14": "", "r15": "", "rbp": "", "rsp": "", "rip": ""}
registersOfFunctions = {}
registersOrder = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

#Program JSON
jsonProgram = {}

def printRegisters(nameFunction):
    print "-------------REGISTERS: " + nameFunction + "-----------"
    for register in registersOfFunctions[nameFunction]:
        print register + ": " + registersOfFunctions[nameFunction][register]
    print "-------------REGISTERS: " + nameFunction + "-----------"


def inspectVulnerability(variables, instruction, nameFunction, index):
    destAddress = registersOfFunctions[nameFunction][registersOrder[0]]
    destVariable = {}

    for variable in variables:
        if variable[CONST_ADDRESS] in destAddress:
            destVariable = variable
    
    #fgets
    if index == 0:
        sizeOfBuffer = hex(destVariable[CONST_BYTES])
        sizeOfInput = registersOfFunctions[nameFunction][CONST_ESI]
        if sizeOfInput > sizeOfBuffer:
            print "Exists Vulnerability: " + dangerousFunctions[index]
            return True
    
    #strcpy
    if index == 1:
        srcAddress = registersOfFunctions[nameFunction][registersOrder[1]]
        srcVariable = {}
        for function in jsonProgram:
            for variable in jsonProgram[function][CONST_VARIABLES]:
                if variable[CONST_ADDRESS] in srcAddress:
                    srcVariable = variable
        
        sizeOfSrcVariable = hex(srcVariable[CONST_BYTES])
        sizeOfBuffer = hex(destVariable[CONST_BYTES])
        if sizeOfSrcVariable > sizeOfBuffer:
            print "Exists Vulnerability: " + dangerousFunctions[index] 
            return True
    #gets
    if index == 6:
       return False
    
    print "No Vulnerability at " + dangerousFunctions[index]
    return False


def doRegisterOperation(instruction, nameFunction):
    operation = instruction[CONST_OPERATION]
    dest = instruction[CONST_ARGS][CONST_DEST]
    value = instruction[CONST_ARGS][CONST_VALUE]

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
        printRegisters(nameFunction)
        return dangerousFunctions.index(functionName) 
    return -1
        
def checkFunction(function, nameFunction):
    variables = function[CONST_VARIABLES]
    instructions = function[CONST_INSTRUCTIONS]

    for instruction in instructions:
        operation = instruction[CONST_OPERATION]
        
        #verifying call function
        if operation == CONST_CALL_OPERATION:
            index = checkOperationCall(instruction, nameFunction)
            if index != -1:
                inspectVulnerability(variables, instruction, nameFunction, index)
            continue

        if operation in assemblyInstructions[CONST_BASIC]:
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

