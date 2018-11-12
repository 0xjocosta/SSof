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
CONST_EDX = "edx" 
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
variablesProgram = {}

#Actual Function
global actualFunction
actualFunction = CONST_MAIN
global previousFunction

def printRegisters():
    print "-------------REGISTERS: -----------"
    for register in registersOfFunctions:
        print register + ": " + registersOfFunctions[register]
    print "-------------REGISTERS: -----------"


def checkOtherOverflow(sizeOfOverflow, nameFunction):
    print sizeOfOverflow
    print "function: " + nameFunction
    print variablesProgram[nameFunction]
    return 


def inspectVulnerability(instruction, index):
    destAddress = registersOfFunctions[registersOrder[0]]
    destVariable = {}
    
    idxDestVariable = 0
    nFunction = ""
    for function in variablesProgram:
        for variable in variablesProgram[function]:
            if variable[CONST_ADDRESS] in destAddress:
                destVariable = variable
                idxDestVariable = variablesProgram[function].index(variable)
                nFunction = function
    
    sizeOfDest = hex(destVariable[CONST_BYTES])
    if registersOrder[1] in registersOfFunctions:
        srcAddress = registersOfFunctions[registersOrder[1]]
        if srcAddress != destAddress:
            srcVariable = {}
            
            for function in variablesProgram:
                for variable in variablesProgram[function]:
                    if variable[CONST_ADDRESS] in srcAddress:
                        srcVariable = variable
                        break
            

            if CONST_EDX in registersOfFunctions:
                sizeOfSrc = registersOfFunctions[CONST_EDX]
            else:
                sizeOfSrc = hex(srcVariable[CONST_BYTES])

            if sizeOfSrc > sizeOfDest:
                sizeOfOverflow = int(sizeOfSrc, 0) - int(sizeOfDest,0)
                print "Exists Variable Overflow: " + instruction[CONST_ARGS][CONST_FNNAME]
                checkOtherOverflow(hex(sizeOfOverflow), nFunction)
                return True
            
    elif CONST_ESI in registersOfFunctions:
        sizeOfInput = registersOfFunctions[CONST_ESI]
        if sizeOfInput > sizeOfDest:
            sizeOfOverflow = int(sizeOfInput, 0) - int(sizeOfDest,0)
            print "Exists Variable Overflow: " + instruction[CONST_ARGS][CONST_FNNAME]
            checkOtherOverflow(hex(sizeOfOverflow), nFunction)
            return True
        else:
            variablesProgram[nFunction][idxDestVariable][CONST_BYTES] = int(sizeOfInput, 0)
    
    else:
        print "Exists Variable Overflow: " + instruction[CONST_ARGS][CONST_FNNAME]
        checkOtherOverflow(999, nFunction)
        return True


    print "No Vulnerability at " + dangerousFunctions[index]
    return False

def doRegisterOperation(instruction):
    operation = instruction[CONST_OPERATION]
    dest = instruction[CONST_ARGS][CONST_DEST]
    value = instruction[CONST_ARGS][CONST_VALUE]

    if value in registersOfFunctions:
        value = registersOfFunctions[value]
        
    if operation in registerOperations:
        if dest not in registersOfFunctions:
            registersOfFunctions[dest] = registerOperations[operation] + value
        else:
            registersOfFunctions[dest] += registerOperations[operation] + value
    else:
        registersOfFunctions[dest] = value

    #for register in registersOfFunctions[nameFunction]:
    #    if dest == registersOfFunctions[nameFunction][register]:
    #        registersOfFunctions[nameFunction][register] = registersOfFunctions[nameFunction][dest]

    #printRegisters()

def checkOperationCall(instruction, actualFunction):
    functionName = instruction[CONST_ARGS][CONST_FNNAME]
    if functionName in dangerousFunctions:
        return dangerousFunctions.index(functionName)
    
    for fName in jsonProgram:
        if fName in functionName:
            checkFunction(jsonProgram[fName], fName)
            return -1
    return -1
        
def checkFunction(function, actualFunction):
    variablesProgram[actualFunction] = function[CONST_VARIABLES]
    instructions = function[CONST_INSTRUCTIONS]

    for instruction in instructions:
        operation = instruction[CONST_OPERATION]
        
        #verifying call function
        if operation == CONST_CALL_OPERATION:
            index = checkOperationCall(instruction, actualFunction)
            if index != -1:
                inspectVulnerability(instruction, index)
            continue

        if operation in assemblyInstructions[CONST_BASIC]:
            doRegisterOperation(instruction)

#Main 
if(len(sys.argv) < 2):
    print "No program received!"
    exit()

with open(str(sys.argv[1])) as json_data:
    jsonProgram = json.load(json_data)

checkFunction(jsonProgram[CONST_MAIN], CONST_MAIN)

