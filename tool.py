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

#Others
CONST_TRASH = "TRASH"
CONST_ZERO = "00"

#Vulnerability outputs
CONST_VULN = "vulnerability"
CONST_VULNFN = "vuln_function"
CONST_OVERFLWVAR = "overflow_var"

CONST_VAROFLW = "VAROVERFLOW"
CONST_RBPOFLW = "RBPOVERFLOW"
CONST_RETOFLW = "RETOVERFLOW"

#Dangerous functions
dangerousFunctions = ({"<fgets@plt>": 1}, {"<strcpy@plt>" : 2}, {"<strcat@plt>": 2}, {"<sprintf@plt>": 0}, {"<fscanf@plt>": 0}, {"<scanf@plt>": 0}, {"<gets@plt>": 1}, {"<strncpy@plt>": 2}, {"<strncat@plt>": 2}, {"<snprintf@plt>": 0}, {"<read@plt>": 1})
CONST_GETS = "gets"
CONST_FGETS = "fgets"
CONST_STRCPY = "strcpy"
CONST_STRNCPY = "strncpy"
CONST_STRCAT = "strcat"
CONST_STRNCAT = "strncat"
CONST_FSCANF = "fscanf"
CONST_SCANF = "scanf"
CONST_SPRINTF = "sprintf"
CONST_SNPRINTF = "snprintf"
CONST_READ = "read"

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

def writeToMemory(addr, size, value, withEOF):
    print "first addr: " + addr,
    print "size: " + str(size)
    count = int(addr[4:], 0)
    addr = addr[0:4]
    maxSize = count + size

    while(count != maxSize):
        pos = addr + hex(count)
        if value != CONST_TRASH and value != CONST_ZERO:
            writeToAddress(pos, memory[value])
            iteration = int(value[4:], 0) + 1
            value = value[0:4] + hex(iteration)
        else:
            writeToAddress(pos, value)
        count += 1

    if withEOF:
        addr = addr + hex(count)
        writeToAddress(addr, "EOF")
    else:
        pos = addr + hex(count)
        writeToAddress(pos, value)
        count += 1

def copyToMemory(srcAddr, destAddr, size, withEOF):
    writeToMemory(destAddr, size, srcAddr, withEOF)

def getSizeOfBuffer(address):
    size = 0
    while True:
        value = memory[address]
        if value == "EOF":
            return size

        count = int(address[4:], 0) + 1
        address = address[0:4] + hex(count)
        size += 1

def getAddrEOF(varName):
    address = variablesProgram[varName][CONST_ADDRESS]
    while True:
        value = memory[address]
        if value == "EOF":
            return address

        count = int(address[4:], 0) + 1
        address = address[0:4] + hex(count)

def checkOtherOverflow(sizeOfOverflow, varName):
    print "sizeOfOverflow: " + sizeOfOverflow
    addrEOF = getAddrEOF(varName)
    print "Address EOF: " + addrEOF
    
    return


#def functionNameConverter(fnName)

def outputOverFlow(instruction, nameVar, fnName, overflowType):
    output[CONST_VULN] = overflowType
    output[CONST_VULNFN] = fnName
    output[CONST_ADDRESS] = instruction[CONST_ARGS][CONST_ADDRESS]
    output[CONST_FNNAME] = instruction[CONST_ARGS][CONST_FNNAME]
    output[CONST_OVERFLWVAR] = nameVar
    return output

#def overflowType()

def inspectVulnerability(instruction, inputs, fnName):
    callFnName = instruction[CONST_ARGS][CONST_FNNAME]

    destAddress = registersOfFunctions[registersOrder[0]]
    destVariable = {}

    nameVar = ""
    for var in variablesProgram:
        variable = variablesProgram[var]
        if variable[CONST_ADDRESS] in destAddress:
            destVariable = variable
            nameVar = var

    sizeOfDest = hex(destVariable[CONST_BYTES])
    sizeOfDestInt = int(sizeOfDest, 0)
    #fgets, gets
    if inputs == 1:
        if CONST_ESI in registersOfFunctions:
            sizeOfInputInt = int(registersOfFunctions[CONST_ESI],0)
        else:
            sizeOfInputInt = -1

        if sizeOfInputInt != -1:
            #fgets
            if sizeOfInputInt > sizeOfDestInt and sizeOfInputInt >= 0:
                writeToMemory(destAddress[1:-1], sizeOfInputInt, CONST_TRASH, True)
                sizeOfOverflow = sizeOfInputInt - sizeOfDestInt
                print "Exists Variable Overflow: " + callFnName
                #output = outputOverFlow(instruction, nameVar, fnName,overflowType=)
                checkOtherOverflow(hex(sizeOfOverflow), nameVar)
                return True

            else:
                writeToMemory(destAddress[1:-1], sizeOfInputInt, CONST_TRASH, True)
                variablesProgram[nameVar][CONST_BYTES] = sizeOfInputInt
                print "No Vulnerability at " + callFnName
                return False

        if sizeOfInputInt == -1:
            #gets
            print "Exists Variable Overflow: " + callFnName
            #checkOtherOverflow(hex(sizeOfOverflow), nameVar)
            #writeToMemory()
            return True

        print "No Vulnerability at " + callFnName
        return False

    #strcpy, strncpy, strcat, strncat
    elif inputs == 2:
        srcAddress = registersOfFunctions[registersOrder[1]]
        srcVariable = {}
        withEOF = True

        for var in variablesProgram:
            variable = variablesProgram[var]
            if variable[CONST_ADDRESS] in srcAddress:
                srcVariable = variable
                break

        if CONST_EDX in registersOfFunctions:
            #strncat, strncpy
            if CONST_STRNCAT in callFnName:
                sizeOfSrcInt = int(registersOfFunctions[CONST_EDX], 0) + 1 #'\0'
                sizeOfSrc = hex(sizeOfSrcInt)
                withEOF = True

            if CONST_STRNCPY in callFnName:
                sizeOfSrc = registersOfFunctions[CONST_EDX]
                sizeOfSrcInt = int(registersOfFunctions[CONST_EDX], 0)
                withEOF = False
        else:
            #strcat, strcpy
            sizeOfSrcInt = getSizeOfBuffer(srcAddress[1:-1])
            sizeOfSrc = hex(sizeOfSrcInt)
            withEOF = True

        print "sizeOfSrc: " + sizeOfSrc
        print "sizeOfDest: " + sizeOfDest
        if sizeOfSrcInt > sizeOfDestInt:
            sizeOfOverflow = sizeOfSrcInt - sizeOfDestInt
            print "Exists Variable Overflow: " + callFnName
            copyToMemory(srcAddress[1:-1], destAddress[1:-1], sizeOfSrcInt, withEOF)
            checkOtherOverflow(hex(sizeOfOverflow), nameVar)
            return True

        print "No Vulnerability at " + callFnName
        copyToMemory(srcAddress[1:-1], destAddress[1:-1], sizeOfSrcInt, withEOF)
        return False

    elif inputs == 3:
        return

    print "No Vulnerability at " + callFnName
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

    for variable in function[CONST_VARIABLES]:
        size = variable[CONST_BYTES]
        address = variable[CONST_ADDRESS]
        dic[address] = size

    for address in sorted (dic.keys()):
        writeToMemory(address, dic[address], CONST_ZERO, False)


def checkFunction(function, fnName):
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
                inspectVulnerability(instruction, index, fnName)
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

checkFunction(jsonProgram[CONST_MAIN], CONST_MAIN)
