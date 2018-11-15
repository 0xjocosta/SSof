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
CONST_EMPTY = ""
CONST_RBP = "rbp+0x0"
CONST_WRITE_EVERYTHNG = 17

#Vulnerability outputs
CONST_VULN = "vulnerability"
CONST_VULNFN = "vuln_function"
CONST_OFVAR = "overflow_var"
CONST_OFNVAR = "overflown_var"
CONST_OFNADDR = "overflown_address"

CONST_VAROFLW = "VAROVERFLOW"
CONST_RBPOFLW = "RBPOVERFLOW"
CONST_RETOFLW = "RETOVERFLOW"
CONST_INVALIDACC = "INVALIDACCS"
CONST_SCORRUPTION = "SCORRUPTION"

#Vulnerabilities tuple
vulnList = (CONST_RBPOFLW,  CONST_RETOFLW, CONST_SCORRUPTION)

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

#Output JSON
outputJSON = []

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
    if count >= 0:
        address = address[0:3] + CONST_PLUS + hex(count)
    else:
        address = address[0:3] + hex(count)
    return address

def decrementAddress(address):
    address = parseAddress(address)

    count = int(address[3:], 0) - 1
    if count >= 0:
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
    #addr
    invalidAddrs = []

    addr = parseAddress(addr)
    print "first addr: " + addr
    print "size: " + str(size)
    count = getCountOfAddress(addr)
    maxSize = count + size - 1
    while(count != maxSize):
        if addr not in memory and value != CONST_ZERO:
            invalidAddrs.append(addr)
            addr = incrementAddress(addr)
            count += 1
            continue

        if value != CONST_TRASH and value != CONST_ZERO:
            value = parseAddress(value)
            writeToAddress(addr, memory[value])
            value = incrementAddress(value)
        else:
            writeToAddress(addr, value)

        addr = incrementAddress(addr)
        count += 1

        if addr == CONST_LIMIT_ADDR:
            return addr, invalidAddrs

    if withEOF:
        writeToAddress(addr, "EOF")
        return addr, invalidAddrs
    else:
        if value != CONST_TRASH and value != CONST_ZERO:
            writeToAddress(addr, memory[value])
            return addr, invalidAddrs
        else:
            writeToAddress(addr, value)
            return addr, invalidAddrs

def copyToMemory(srcAddr, destAddr, size, withEOF):
    return writeToMemory(destAddr, size, srcAddr, withEOF)

def getSizeOfBuffer(address):
    address = parseAddress(address)
    size = 1
    while True:
        if address == CONST_LIMIT_ADDR:
            return size
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

def getMemoryAddrs(firstAddr, lastAddress):
    addresses = {}

    firstAddr = parseAddress(firstAddr)
    lastAddress = parseAddress(lastAddress)
    while firstAddr != lastAddress:
        addresses[firstAddr] = memory[firstAddr]
        firstAddr = incrementAddress(firstAddr)

    memory[firstAddr] = memory[firstAddr]
    return addresses

def overflownVariables(addrEOF, nameVar):
    overflwnVariables = []

    overflowerAddr = parseAddress(variablesProgram[nameVar][CONST_ADDRESS])
    intOverflowerAddr = getCountOfAddress(overflowerAddr)

    addrEOF = parseAddress(addrEOF)
    intEOF = getCountOfAddress(addrEOF)
    for var in variablesProgram:
        addrVariable = variablesProgram[var][CONST_ADDRESS]
        addrVariable = parseAddress(addrVariable)
        print "eof:" + addrEOF
        print "var: " + addrVariable
        print "over:" + overflowerAddr
        intAddrVariable = getCountOfAddress(addrVariable)
        if intEOF >= intAddrVariable > intOverflowerAddr and addrVariable != overflowerAddr:
            overflwnVariables.append(var)

    return overflwnVariables

def outputOverflow(instruction, nameVar, vulnFnName, overflowType, fnName, overFlown = CONST_EMPTY):
    output = {}
    if overflowType == CONST_VAROFLW:
        output[CONST_OFNVAR] = overFlown

    if overflowType == CONST_SCORRUPTION:
        output[CONST_OFNADDR] = CONST_LIMIT_ADDR

    if overflowType == CONST_INVALIDACC:
        output[CONST_OFNADDR] = overFlown

    output[CONST_VULN] = overflowType
    output[CONST_VULNFN] = vulnFnName
    output[CONST_ADDRESS] = instruction[CONST_ADDRESS]
    output[CONST_FNNAME] = fnName
    output[CONST_OFVAR] = nameVar #funcao de buffers recursivos
    return output

def outputOverflown(instruction, nameVar, vulnFnName, fnName , addrEOF):
    array = []
    overflwnVariables = overflownVariables(addrEOF, nameVar)
    for var in overflwnVariables:
        array.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_VAROFLW, fnName, var))
    return array

def checkOverflowType(instruction, nameVar, vulnFnName, fnName, lastAddress):
    lastAddress = parseAddress(lastAddress)

    print "Writed last address: " + lastAddress
    value = getCountOfAddress(lastAddress)

    if CONST_PLUS in lastAddress:
        if value >= 16:
            print "overflow vars, rbp, retAddr, SCORRUPTION"
            outputJSON.extend(outputOverflown(instruction, nameVar, vulnFnName, fnName, lastAddress))
            for i in range(len(vulnList)):
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

        elif value >= 8:
            print "overflow vars, rbp, retAddr"
            outputJSON.extend(outputOverflown(instruction, nameVar, vulnFnName, fnName, lastAddress))
            for i in range(len(vulnList)-1):
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

        elif value >= 0:
            print "overflow vars, rbp"
            outputJSON.extend(outputOverflown(instruction, nameVar, vulnFnName, fnName, lastAddress))
            for i in range(len(vulnList)-2):
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

    elif CONST_MINUS in lastAddress:
        print "overflow vars"
        outputJSON.extend(outputOverflown(instruction, nameVar, vulnFnName, fnName, lastAddress))

    else:
        print "nothing else"
        return

def inspectVulnerability(instruction, inputs, vulnFnName):
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
    print destVariable

    if CONST_FGETS in callFnName:

        sizeOfInputInt = int(registersOfFunctions[CONST_ESI],0)
        if sizeOfInputInt > sizeOfDestInt:

            lastAddress, invalidAddrs = writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, True)
            if len(invalidAddrs) > 0:
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_FGETS, invalidAddrs[0]))
            print "Exists Variable Overflow: " + callFnName
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_FGETS, lastAddress)
            return True

        else:
            writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, True)
            #variablesProgram[nameVar][CONST_BYTES] = sizeOfInputInt
            print "No Vulnerability at " + callFnName
            return False

    if CONST_GETS in callFnName:

        print "Exists Variable Overflow: " + callFnName
        count = getCountOfAddress(destAddress)
        sizeOfInputInt = CONST_WRITE_EVERYTHNG - count
        lastAddress, invalidAddrs = writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
        if len(invalidAddrs) > 0:
            outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_GETS, invalidAddrs[0]))
        checkOverflowType(instruction, nameVar, vulnFnName, CONST_GETS, lastAddress)
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
            lastAddress, invalidAddrs = writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
            if len(invalidAddrs) > 0:
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_READ, invalidAddrs[0]))
            print "Exists Variable Overflow: " + callFnName
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_READ, lastAddress)
            return True

        else:
            writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
            #variablesProgram[nameVar][CONST_BYTES] = sizeOfInputInt
            print "No Vulnerability at " + callFnName
            return False
        return

    if CONST_SCANF in callFnName:
        destAddress = srcAddress

        print "Exists Variable Overflow: " + callFnName
        count = getCountOfAddress(destAddress)
        sizeOfInputInt = 10 - count
        lastAddress, invalidAddrs = writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
        if len(invalidAddrs) > 0:
            outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_SCANF, invalidAddrs[0]))
        checkOverflowType(instruction, nameVar, vulnFnName, CONST_SCANF, lastAddress)
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
        lastAddress, invalidAddrs = writeToMemory(destAddress, sizeOfInputInt, CONST_TRASH, False)
        if len(invalidAddrs) > 0:
            outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_FSCANF, invalidAddrs[0]))
        checkOverflowType(instruction, nameVar, vulnFnName, CONST_FSCANF, lastAddress)
        return True

    if CONST_STRNCAT in callFnName:
        sizeOfSrcInt = int(registersOfFunctions[CONST_EDX], 0) + 1 #'\0'
        sizeOfSrc = hex(sizeOfSrcInt)
        withEOF = True

        endOfStringAddr = getAddrEOF(nameVar)
        sizeOfStr = getSizeOfBuffer(destAddress) - 1 #free the '\0'
        print "sizeOfStr -> " + str(sizeOfStr)
        print "sizeOfSrcInt -> " + str(sizeOfSrcInt)
        print "sizeOfDestInt -> " + str(sizeOfDestInt)
        if sizeOfSrcInt + sizeOfStr > sizeOfDestInt:
            print "Exists Variable Overflow: " + callFnName
            lastAddress, invalidAddrs = copyToMemory(srcAddress, endOfStringAddr, sizeOfSrcInt, withEOF)
            if len(invalidAddrs) > 0:
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_STRNCAT, invalidAddrs[0]))
            print "size of buffer: " + str(getSizeOfBuffer(destAddress))
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_STRNCAT, lastAddress)
            return True

        print "No Vulnerability at " + callFnName
        copyToMemory(srcAddress, endOfStringAddr, sizeOfSrcInt, withEOF)
        return False

    if CONST_STRCAT in callFnName:
        sizeOfSrcInt = getSizeOfBuffer(srcAddress)
        sizeOfSrc = hex(sizeOfSrcInt)
        withEOF = True

        endOfStringAddr = getAddrEOF(nameVar)
        sizeOfStr = getSizeOfBuffer(destAddress)
        if sizeOfSrcInt + sizeOfStr > sizeOfDestInt:
            print "Exists Variable Overflow: " + callFnName
            lastAddress, invalidAddrs = copyToMemory(srcAddress, endOfStringAddr, sizeOfSrcInt, withEOF)
            if len(invalidAddrs) > 0:
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_STRCAT, invalidAddrs[0]))
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_STRCAT, lastAddress)
            return True

        print "No Vulnerability at " + callFnName
        copyToMemory(srcAddress, endOfStringAddr, sizeOfSrcInt, withEOF)
        return False

    if CONST_STRNCPY in callFnName:
        sizeOfSrc = registersOfFunctions[CONST_EDX]
        sizeOfSrcInt = int(registersOfFunctions[CONST_EDX], 0)
        withEOF = False

        if sizeOfSrcInt > sizeOfDestInt:
            print "Exists Variable Overflow: " + callFnName
            lastAddress, invalidAddrs = copyToMemory(srcAddress, destAddress, sizeOfSrcInt, withEOF)
            if len(invalidAddrs) > 0:
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_STRNCPY, invalidAddrs[0]))
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_STRNCPY, lastAddress)
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
            lastAddress, invalidAddrs = copyToMemory(srcAddress, destAddress, sizeOfSrcInt, withEOF)
            if len(invalidAddrs) > 0:
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_STRCPY, invalidAddrs[0]))
            checkOverflowType(instruction, nameVar, vulnFnName, CONST_STRCPY, lastAddress)
            return True

        print "No Vulnerability at " + callFnName
        copyToMemory(srcAddress, destAddress, sizeOfSrcInt, withEOF)
        return False

    if CONST_FSCANF in callFnName:
        return

    if CONST_FSCANF in callFnName:
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

    writeToMemory(CONST_RBP, 16, CONST_ZERO, False)

    for address in sorted (dic.keys()):
        writeToMemory(address, dic[address], CONST_ZERO, True)

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

def settingName(fileName):
    return fileName[:19] + "outputs/" + fileName[19:-5] + ".myoutput.json"

#Main
if(len(sys.argv) < 2):
    print "No program received!"
    exit()

fileName = str(sys.argv[1])
with open(fileName) as json_data:
    jsonProgram = json.load(json_data)

checkFunction(jsonProgram[CONST_MAIN], CONST_MAIN)
print outputJSON
with open(settingName(fileName), 'w') as outfile:
    json.dump(outputJSON, outfile)
