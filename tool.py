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

CONST_PLUS = "+"
CONST_MINUS = "-"

CONST_ESI = "esi"
CONST_EDI = "edi"
CONST_EDX = "edx"
CONST_ADDRESS = "address"
CONST_BYTES = "bytes"
CONST_NAME = "name"

CONST_MAIN = "main"

#Others
CONST_TRASH = "TRASH"
CONST_ZERO = "00"
CONST_LIMIT_ADDR = "rbp+0x10"

#Vulnerability outputs
CONST_VULN = "vulnerability"
CONST_VULNFN = "vuln_function"
CONST_OFVAR = "overflow_var"
CONST_OFNVAR = "overflown_var"

CONST_VAROFLW = "VAROVERFLOW"
CONST_RBPOFLW = "RBPOVERFLOW"
CONST_RETOFLW = "RETOVERFLOW"
CONST_INVALIDACC = "INVALIDACCS"
CONST_SCORRUPTION = "SCORRUPTION"

#Vulnerabilities tuple
vulnList=(CONST_RBPOFLW,  CONST_RETOFLW, CONST_SCORRUPTION)

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

def parseAddress(address):
    if "[" in address:
        return address[1:-1]
    else:
        return address

def incrementAddress(address):
    address = parseAddress(address)
    count = int(address[3:], 0) + 1
    if count > 0:
        address = address[0:3] + CONST_PLUS + hex(count)
    else:
        address = address[0:3] + hex(count)
    return address

def decrementAddress(address):
    address = parseAddress(address)

    count = int(address[3:], 0) - 1
    if count > 0:
        address = address[0:3] + CONST_PLUS + hex(count)
    else:
        address = address[0:3] + hex(count)
    return address

def getCountOfAddress(address):
    address = parseAddress(address)
    return int(address[3:], 0)

def writeToAddress(address ,value):
    memory[address] = value

def writeToMemory(addr, size, value, withEOF):
    addr = parseAddress(addr)
    print "first addr: " + addr
    print "size: " + str(size)
    count = getCountOfAddress(addr)
    maxSize = count - size

    while(count != maxSize):
        if value != CONST_TRASH and value != CONST_ZERO:
            value = parseAddress(value)
            writeToAddress(addr, memory[value])
            value = incrementAddress(value)
        else:
            writeToAddress(addr, value)

        addr = incrementAddress(addr)
        count -= 1

        if addr == CONST_LIMIT_ADDR:
            return addr

    if withEOF:
        writeToAddress(addr, "EOF")
        return addr
    else:
        if value != CONST_TRASH and value != CONST_ZERO:
            writeToAddress(addr, memory[value])
            return addr
        else:
            writeToAddress(addr, value)
            return addr

def copyToMemory(srcAddr, destAddr, size, withEOF):
    writeToMemory(destAddr, size, srcAddr, withEOF)

def getSizeOfBuffer(address):
    address = parseAddress(address)
    size = 0
    while True:
        value = memory[address]
        if value == "EOF":
            return size

        address = incrementAddress(address)
        size += 1

def getAddrEOF(varName):
    address = variablesProgram[varName][CONST_ADDRESS]
    address = parseAddress(address)
    while True:
        if address == CONST_LIMIT_ADDR:
            return address
        value = memory[address]
        if value == "EOF":
            return address

        address = incrementAddress(address)

def overflownVariables(addrEOF):
    overflwnVariables = []

    addrEOF = parseAddress(addrEOF)
    for variable in variablesProgram:
        addrVariable = variable[CONST_ADDRESS]
        addrVariable = parseAddress(addrVariable)
        if not addrEOF > addrVariable:
            overflwnVariables.append(variable[CONST_NAME])

    return overflwnVariables

def outputOverflow(instruction, nameVar, vulnFnName, overflowType, fnName, overFlownVar=CONST_EMPTY):
    output = {}
    if overflowType == CONST_VAROFLW:
        output[CONST_OFNVAR] = overFlownVar
    output[CONST_VULN] = overflowType
    output[CONST_VULNFN] = fnName
    output[CONST_ADDRESS] = instruction[CONST_ARGS][CONST_ADDRESS]
    output[CONST_FNNAME] = instructionFn
    output[CONST_OFVAR] = nameVar #funcao de buffers recursivos

    return output

def outputOverflown(instruction, nameVar, vulnFnName, fnName , addrEOF):
    array = []
    overflownVariables = overflownVariables(addrEOF)
    for var in overflownVariables:
        array.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_VAROFLW, fnName, var))
    return array

def checkOverflowType(instruction, nameVar, vulnFnName, fnName):
    arrayVul = []

    addrEOF = getAddrEOF(nameVar)
    print "Address EOF: " + addrEOF
    value = int(addrEOF[4:],0)

    if CONST_PLUS in addrEOF:
        if value >= 16:
            print "overflow vars, rbp, retAddr, SCORRUPTION"
            arrayVul.extend(outputOverflown(instruction, nameVar, vulnFnName, fnName, addrEOF))
            for i in range(len(vulnList)):
                arrayVul.append(outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

        elif value >= 8:
            print "overflow vars, rbp, retAddr"
            arrayVul.extend(outputOverflown(instruction, nameVar, vulnFnName, fnName, addrEOF))
            for i in range(len(vulnList)-1):
                arrayVul.append(outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

        elif value >= 0:
            print "overflow vars, rbp"
            arrayVul.extend(outputOverflown(instruction, nameVar, vulnFnName, fnName, addrEOF))
            for i in range(len(vulnList)-2):
                arrayVul.append(outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

    elif CONST_MINUS in addrEOF:
        print "overflow vars"
        arrayVul.extend(outputOverflown(instruction, nameVar, vulnFnName, fnName, addrEOF))

    else:
        print "nothing else"
        return

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

    if CONST_FGETS in callFnName:

        sizeOfInputInt = int(registersOfFunctions[CONST_ESI],0)
        if sizeOfInputInt > sizeOfDestInt:
            writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, True)
            print "Exists Variable Overflow: " + callFnName
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_FGETS)
            return True

        else:
            writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, True)
            variablesProgram[nameVar][CONST_BYTES] = sizeOfInputInt
            print "No Vulnerability at " + callFnName
            return False

    if CONST_GETS in callFnName:

        print "Exists Variable Overflow: " + callFnName
        count = getCountOfAddress(destAddress)
        sizeOfInputInt = 10 - count
        writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
        checkOverflowType(instruction, nameVar, vulnFnName, CONST_GETS)
        return True

    srcAddress = registersOfFunctions[registersOrder[1]]
    srcVariable = {}
    for var in variablesProgram:
        variable = variablesProgram[var]
        if variable[CONST_ADDRESS] in srcAddress:
            srcVariable = variable
            break

    if CONST_READ in callFnName:
        sizeOfInputInt = int(registersOfFunctions[CONST_EDX],0)
        destAddress = srcAddress
        destVariable = srcVariable

        sizeOfDest = hex(destVariable[CONST_BYTES])
        sizeOfDestInt = int(sizeOfDest, 0)
        if sizeOfInputInt > sizeOfDestInt:
            writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
            print "Exists Variable Overflow: " + callFnName
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_READ)
            return True

        else:
            writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
            variablesProgram[nameVar][CONST_BYTES] = sizeOfInputInt
            print "No Vulnerability at " + callFnName
            return False
        return

    if CONST_SCANF in callFnName:
        destAddress = srcAddress

        print "Exists Variable Overflow: " + callFnName
        count = getCountOfAddress(destAddress)
        sizeOfInputInt = 10 - count
        writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
        checkOverflowType(instruction, nameVar, vulnFnName, CONST_SCANF)
        return True

    if CONST_FSCANF in callFnName:
        destAddress = registersOfFunctions[registersOrder[2]]
        destVariable = {}
        for var in variablesProgram:
            variable = variablesProgram[var]
            if variable[CONST_ADDRESS] in destAddress:
                destVariable = variable
                break

        print "Exists Variable Overflow: " + callFnName
        count = getCountOfAddress(destAddress)
        sizeOfInputInt = 10 - count
        writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
        checkOverflowType(instruction, nameVar, vulnFnName, CONST_FSCANF)
        return True

    if CONST_STRNCAT in callFnName:
        sizeOfSrcInt = int(registersOfFunctions[CONST_EDX], 0) + 1 #'\0'
        sizeOfSrc = hex(sizeOfSrcInt)
        withEOF = True

        sizeOfStr = getSizeOfBuffer(destAddr)
        destAddr = getAddrEOF(nameVar)
        if sizeOfSrcInt + sizeOfStr > sizeOfDestInt:
            print "Exists Variable Overflow: " + callFnName
            copyToMemory(srcAddress, destAddr, sizeOfSrcInt, withEOF)
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_STRNCAT)
            return True

        print "No Vulnerability at " + callFnName
        copyToMemory(srcAddress, destAddr, sizeOfSrcInt, withEOF)
        return False

    if CONST_STRCAT in callFnName:
        sizeOfSrcInt = getSizeOfBuffer(srcAddress)
        sizeOfSrc = hex(sizeOfSrcInt)
        withEOF = True

        sizeOfStr = getSizeOfBuffer(destAddr)
        destAddr = getAddrEOF(nameVar)
        if sizeOfSrcInt + sizeOfStr > sizeOfDestInt:
            print "Exists Variable Overflow: " + callFnName
            copyToMemory(srcAddress, destAddr, sizeOfSrcInt, withEOF)
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_STRCAT)
            return True

        print "No Vulnerability at " + callFnName
        copyToMemory(srcAddress, destAddr, sizeOfSrcInt, withEOF)
        return False

    if CONST_STRNCPY in callFnName:
        sizeOfSrc = registersOfFunctions[CONST_EDX]
        sizeOfSrcInt = int(registersOfFunctions[CONST_EDX], 0)
        withEOF = False

        if sizeOfSrcInt > sizeOfDestInt:
            print "Exists Variable Overflow: " + callFnName
            copyToMemory(srcAddress, destAddress, sizeOfSrcInt, withEOF)
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_STRNCPY)
            return True

        print "No Vulnerability at " + callFnName
        copyToMemory(srcAddress, destAddress, sizeOfSrcInt, withEOF)
        return False

    if CONST_STRCPY in callFnName:
        sizeOfSrcInt = getSizeOfBuffer(srcAddress)
        sizeOfSrc = hex(sizeOfSrcInt)
        withEOF = True

        if sizeOfSrcInt > sizeOfDestInt:
            print "Exists Variable Overflow: " + callFnName
            copyToMemory(srcAddress, destAddress, sizeOfSrcInt, withEOF)
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_STRNCPY)
            return True

        print "No Vulnerability at " + callFnName
        copyToMemory(srcAddress, destAddress, sizeOfSrcInt, withEOF)
        return False

    if CONST_FSCANF in callFnName:
        return

    if CONST_FSCANF in callFnName:
        return

    #fgets, gets
    if inputs == 1:
        if CONST_ESI in registersOfFunctions:
            sizeOfInputInt = int(registersOfFunctions[CONST_ESI],0)
        else:
            sizeOfInputInt = -1

        if sizeOfInputInt != -1:
            #fgets
            if sizeOfInputInt > sizeOfDestInt and sizeOfInputInt >= 0:
                writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, True)
                print "Exists Variable Overflow: " + callFnName
                #output = outputOverflow(instruction, nameVar, fnName,overflowType=)
                checkOverflowType(instruction, nameVar, fnName)
                return True

            else:
                writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, True)
                variablesProgram[nameVar][CONST_BYTES] = sizeOfInputInt
                print "No Vulnerability at " + callFnName
                return False

        if sizeOfInputInt == -1:
            #gets
            print "Exists Variable Overflow: " + callFnName
            count = getCountOfAddress(destAddress)
            sizeOfInputInt = 10 - count
            writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
            checkOverflowType(instruction, nameVar, fnName)
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

            #strcat, strcpy
            sizeOfSrcInt = getSizeOfBuffer(srcAddress)
            sizeOfSrc = hex(sizeOfSrcInt)
            withEOF = True

        print "sizeOfSrc: " + sizeOfSrc
        print "sizeOfDest: " + sizeOfDest
        if sizeOfSrcInt > sizeOfDestInt:
            sizeOfOverflow = sizeOfSrcInt - sizeOfDestInt
            print "Exists Variable Overflow: " + callFnName
            copyToMemory(srcAddress, destAddress, sizeOfSrcInt, withEOF)
            checkOverflowType(instruction, nameVar, fnName)
            return True

        print "No Vulnerability at " + callFnName
        copyToMemory(srcAddress, destAddress, sizeOfSrcInt, withEOF)
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

    index = 1
    for address in sorted (dic.keys()):
        lastAddress = writeToMemory(address, dic[address], CONST_ZERO, False)
        if index == 1:
            writeToMemory(lastAddress, 16, CONST_ZERO, False)
        index += 1

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
