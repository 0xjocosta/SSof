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

CONST_MAIN = "main"

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

#Variables from JSON Program
variablesProgram = []

def printRegisters(nameFunction):
    print "-------------REGISTERS: " + nameFunction + "-----------"
    for register in registersOfFunctions[nameFunction]:
        print register + ": " + registersOfFunctions[nameFunction][register]
    print "-------------REGISTERS: " + nameFunction + "-----------"


def inspectVulnerability(instruction, nameFunction, index):
    destAddress = registersOfFunctions[nameFunction][registersOrder[0]]
    destVariable = {}
    
    idxDestVariable = 0

    for variable in variablesProgram:
        if variable[CONST_ADDRESS] in destAddress:
            destVariable = variable
            idxDestVariable = variablesProgram.index(variable)
     
    #fgets
    if index == 0:
        sizeOfBuffer = hex(destVariable[CONST_BYTES])
        sizeOfInput = registersOfFunctions[nameFunction][CONST_ESI]
        if sizeOfInput > sizeOfBuffer:
            print "Exists Vulnerability: " + dangerousFunctions[index]
            return True
        else:
            variablesProgram[idxDestVariable][CONST_BYTES] = int(sizeOfInput, 0)
    
    #strcpy, strcat, strncpy, strncat
    if index == 1 or index == 2 or index == 7 or index == 8:
        srcAddress = registersOfFunctions[nameFunction][registersOrder[1]]
        srcVariable = {}
        for variable in variablesProgram:
            if variable[CONST_ADDRESS] in srcAddress:
                srcVariable = variable
        
        sizeOfSrcVariable = hex(srcVariable[CONST_BYTES])
        sizeOfBuffer = hex(destVariable[CONST_BYTES])
        
        if sizeOfSrcVariable > sizeOfBuffer:
            print "Exists Vulnerability: " + dangerousFunctions[index] 
            return True
    #gets
    if index == 6:
        print "Exists Vulnerability: " + dangerousFunctions[index]
        return True

    print "No Vulnerability at " + dangerousFunctions[index]
    return False

def doRegisterOperation(instruction, nameFunction):
    operation = instruction[CONST_OPERATION]
    dest = instruction[CONST_ARGS][CONST_DEST]
    value = instruction[CONST_ARGS][CONST_VALUE]

    if value in registersOfFunctions[nameFunction]:
        value = registersOfFunctions[nameFunction][value]
        
    if operation in registerOperations:
        if dest not in registersOfFunctions[nameFunction]:
            registersOfFunctions[nameFunction][dest] = registerOperations[operation] + value
        else:
            registersOfFunctions[nameFunction][dest] += registerOperations[operation] + value
    else:
        registersOfFunctions[nameFunction][dest] = value

    #for register in registersOfFunctions[nameFunction]:
    #    if dest == registersOfFunctions[nameFunction][register]:
    #        registersOfFunctions[nameFunction][register] = registersOfFunctions[nameFunction][dest]

    printRegisters(nameFunction)

def checkOperationCall(instruction, nameFunction):
    functionName = instruction[CONST_ARGS][CONST_FNNAME]
    if functionName in dangerousFunctions:
        return dangerousFunctions.index(functionName)
    
    for fName in jsonProgram:
        if fName in functionName:
            registersOfFunctions[fName] = registersOfFunctions[nameFunction]
            checkFunction(jsonProgram[fName], fName)
            return -1
    return -1
        
def checkFunction(function, nameFunction):
    variablesProgram.extend(function[CONST_VARIABLES])
    instructions = function[CONST_INSTRUCTIONS]

    for instruction in instructions:
        operation = instruction[CONST_OPERATION]
        
        #verifying call function
        if operation == CONST_CALL_OPERATION:
            index = checkOperationCall(instruction, nameFunction)
            if index != -1:
                inspectVulnerability(instruction, nameFunction, index)
            continue

        if operation in assemblyInstructions[CONST_BASIC]:
            doRegisterOperation(instruction, nameFunction)

#Main 
if(len(sys.argv) < 2):
    print "No program received!"
    exit()

with open(str(sys.argv[1])) as json_data:
    jsonProgram = json.load(json_data)

registersOfFunctions[CONST_MAIN] = {}
checkFunction(jsonProgram[CONST_MAIN], CONST_MAIN)

