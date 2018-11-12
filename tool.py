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
CONST_NAME = "name"

CONST_MAIN = "main"

#Dangerous functions
dangerousFunctions = ({"<fgets@plt>": 1}, {"<strcpy@plt>" : 2}, {"<strcat@plt>": 2}, {"<sprintf@plt>": 0}, {"<fscanf@plt>": 0}, {"<scanf@plt>": 0}, {"<gets@plt>": 1}, {"<strncpy@plt>": 2}, {"<strncat@plt>": 2}, {"<snprintf@plt>": 0}, {"<read@plt>": 1})

#Assembly instructions
assemblyInstructions = {"basic": ["mov", "lea", "sub", "add"], "advanced": ["cmp", "test", "je", "jmp", "jne"]}
registerOperations = {"sub": "-", "add": "+"}

#Registers
registers = ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rbp", "rsp", "rip"]
registersOfFunctions = {}
registersOrder = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

#Program JSON
jsonProgram = {}

#Variables from JSON Program
variablesProgram = {}

#Memory
memory = {}


def printMemory():
    print "---------Memory---------"
    for addr in sorted (memory.keys()):
        print addr + "-> " + memory[addr]

    print "---------Memory---------"

def printRegisters():
    print "-------------REGISTERS: -----------"
    for register in registersOfFunctions:
        print register + ": " + registersOfFunctions[register]
    print "-------------REGISTERS: -----------"

def writeToAddress(address ,value):
    memory[address] = value

def writeToMemory(addr, size, value):
    count = int(addr[4:], 0)
    addr = addr[0:4]
    maxSize = count + size
    
    while(count != maxSize):
        pos = addr + hex(count)
        writeToAddress(pos, value)
        count += 1
    
    addr = addr + hex(count)
    writeToAddress(addr, "EOF")

def getVariableMemory(varName):
    address = variablesProgram[varName][CONST_ADDRESS]
    variableMemory = {}
    while True:
        value = memory[address]
        if value == "EOF":
            variableMemory[address] = value
            print variableMemory
            return

        variableMemory[address] = value
        count = int(address[4:], 0) + 1
        address = address[0:4] + hex(count)

def checkOtherOverflow(sizeOfOverflow):
    print sizeOfOverflow
    print variablesProgram
    return 


def inspectVulnerability(instruction, inputs):
    destAddress = registersOfFunctions[registersOrder[0]]
    destVariable = {}
    
    nameVar = ""
    for var in variablesProgram:
        variable = variablesProgram[var]
        if variable[CONST_ADDRESS] in destAddress:
            destVariable = variable
            nameVar = var
    
    sizeOfDest = hex(destVariable[CONST_BYTES])
    
    #fgets
    if inputs == 1:
        sizeOfInput = -1
        if CONST_ESI in registersOfFunctions:
            sizeOfInput = registersOfFunctions[CONST_ESI]

        if sizeOfInput > sizeOfDest and sizeOfInput >= 0:
            writeToAddress()
            sizeOfOverflow = int(sizeOfInput, 0) - int(sizeOfDest, 0)
            print "EXIST VUL..."
            checkOtherOverflow(hex(sizeOfOverflow))
            return True
    #
    elif inputs == 2:
        
    elif inputs == 3:
        
    if registersOrder[1] in registersOfFunctions:
        srcAddress = registersOfFunctions[registersOrder[1]]
        if srcAddress != destAddress:
            srcVariable = {}
            
            for var in variablesProgram:
                variable = variablesProgram[var]
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
                checkOtherOverflow(hex(sizeOfOverflow))
                return True
            
    elif CONST_ESI in registersOfFunctions:
        sizeOfInput = registersOfFunctions[CONST_ESI]
        if sizeOfInput > sizeOfDest:
            sizeOfOverflow = int(sizeOfInput, 0) - int(sizeOfDest,0)
            print "Exists Variable Overflow: " + instruction[CONST_ARGS][CONST_FNNAME]
            checkOtherOverflow(hex(sizeOfOverflow))
            return True
        else:
            variablesProgram[nameVar][CONST_BYTES] = int(sizeOfInput, 0)
    
    else:
        print "Exists Variable Overflow: " + instruction[CONST_ARGS][CONST_FNNAME]
        checkOtherOverflow(999)
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

def checkOperationCall(instruction):
    functionName = instruction[CONST_ARGS][CONST_FNNAME]
    for func in dangerousFunctions:
        if functionName in func.keys():
            return func[functionName]
    
    for fName in jsonProgram:
        if fName in functionName:
            checkFunction(jsonProgram[fName], fName)
            return -1
    return -1
        
def cleanRegisters():
    for register in registersOfFunctions.keys():
        if register not in registers:
            del registersOfFunctions[register]

def initializeMemory(function):
    dic = {}
    
    for var in variablesProgram:
        size = variablesProgram[var][CONST_BYTES]
        address = variablesProgram[var][CONST_ADDRESS]
        dic[address] = size
    
    value = "00"
    for address in sorted (dic.keys()):
        writeToMemory(address, dic[address], value)


def checkFunction(function):
    for var in function[CONST_VARIABLES]:
        nameVar = var[CONST_NAME]
        variablesProgram[nameVar] = var
    initializeMemory(function)

    instructions = function[CONST_INSTRUCTIONS]
    for instruction in instructions:
        operation = instruction[CONST_OPERATION]
        
        #verifying call function
        if operation == CONST_CALL_OPERATION:
            index = checkOperationCall(instruction)
            if index != -1:
                inspectVulnerability(instruction, index)
            continue

        if operation in assemblyInstructions[CONST_BASIC]:
            doRegisterOperation(instruction)

    cleanRegisters()

#Main 
if(len(sys.argv) < 2):
    print "No program received!"
    exit()

with open(str(sys.argv[1])) as json_data:
    jsonProgram = json.load(json_data)

checkFunction(jsonProgram[CONST_MAIN])
