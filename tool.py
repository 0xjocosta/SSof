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

#SizeSpecifications -> instruction MOV
sizeSpecifications = {"BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8}

#Others
CONST_NULL_CHAR = "0x0"
CONST_EOF = "EOF"
CONST_TRASH = "TRASH"
CONST_ZERO = "00"
CONST_LIMIT_ADDR = "rbp+0x10"
CONST_EMPTY = ""
CONST_RBP = "rbp+0x0"
CONST_WRITE_EVERYTHNG = 17

CONST_MOV = "mov"

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
dangerousFunctions = ("<fgets@plt>", "<strcpy@plt>", "<strcat@plt>", "<sprintf@plt>", "<__isoc99_fscanf@plt>", "<__isoc99_scanf@plt>", "<gets@plt>", "<strncpy@plt>", "<strncat@plt>", "<snprintf@plt>", "<read@plt>")
CONST_GETS = "gets"
CONST_FGETS = "fgets"
CONST_STRCPY = "strcpy"
CONST_STRNCPY = "strncpy"
CONST_STRCAT = "strcat"
CONST_STRNCAT = "strncat"
CONST_FSCANF = "__isoc99_fscanf"
CONST_SCANF = "__isoc99_scanf"
CONST_SPRINTF = "sprintf"
CONST_SNPRINTF = "snprintf"
CONST_READ = "read"

class DangerousFunction(object):
    """docstring for DangerousFunction."""
    def __init__(self, fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt, srcBuffers=[], sizeOfStrInt=0, endOfStringAddr=None):
        super(DangerousFunction, self).__init__()
        self.fnName = fnName
        self.destAddress = destAddress
        self.sizeOfDestInt = sizeOfDestInt
        self.withEOF = withEOF
        self.sizeOfInputInt = sizeOfInputInt
        self.srcBuffers = srcBuffers
        self.sizeOfStrInt = sizeOfStrInt
        self.endOfStringAddr = endOfStringAddr

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
    addr = parseAddress(addr)
    print "first addr: " + addr
    print "size: " + str(size)
    count = getCountOfAddress(addr)
    maxSize = count + size - 1
    while(count != maxSize):
        #invalid address
        if addr not in memory and value != CONST_ZERO:
            addr = incrementAddress(addr)
            count += 1
            continue

        #parse meaningful values
        if value != CONST_TRASH and value != CONST_ZERO and value != CONST_EOF:
            value = parseAddress(value)
            writeToAddress(addr, memory[value])
            value = incrementAddress(value)
        else:
            writeToAddress(addr, value)

        addr = incrementAddress(addr)
        count += 1

        if addr == CONST_LIMIT_ADDR:
            return addr

    #invalid address
    if addr not in memory and value != CONST_ZERO:
        return addr

    if withEOF:
        writeToAddress(addr, CONST_EOF)
        return addr
    else:
        #Copy buffer to another buffer
        if value != CONST_TRASH and value != CONST_ZERO and value != CONST_EOF:
            writeToAddress(addr, memory[value])
            return addr
        #write to buffer
        else:
            writeToAddress(addr, value)
            return addr

def getSizeOfBuffer(address):
    address = parseAddress(address)
    size = 1
    while True:
        if address == CONST_LIMIT_ADDR:
            return size
        value = memory[address]
        if value == CONST_EOF:
            return size

        address = incrementAddress(address)
        size += 1

def getAddrEOF(varName, fnName):
    address = variablesProgram[fnName][varName][CONST_ADDRESS]
    address = parseAddress(address)
    while True:
        if address == CONST_LIMIT_ADDR:
            return address
        value = memory[address]
        if value == CONST_EOF:
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

def getNameAndVariable(addr, fnName):
    destVariable = {}
    nameVar = CONST_EMPTY
    for var in variablesProgram[fnName]:
        variable = variablesProgram[fnName][var]
        if variable[CONST_ADDRESS] in addr:
            destVariable = variable
            nameVar = var
    return nameVar, destVariable

def overflownVariables(addrEOF, nameVar, fnName):
    overflwnVariables = {}

    overflowerAddr = parseAddress(variablesProgram[fnName][nameVar][CONST_ADDRESS])
    intOverflowerAddr = getCountOfAddress(overflowerAddr)

    addrEOF = parseAddress(addrEOF)
    intEOF = getCountOfAddress(addrEOF)
    for var in variablesProgram[fnName]:
        addrVariable = variablesProgram[fnName][var][CONST_ADDRESS]
        addrVariable = parseAddress(addrVariable)
        intAddrVariable = getCountOfAddress(addrVariable)
        if intEOF >= intAddrVariable > intOverflowerAddr and addrVariable != overflowerAddr:
            overflwnVariables[addrVariable] = var

    return overflwnVariables

def outputOverflow(instruction, nameVar, vulnFnName, overflowType, fnName, overFlown = CONST_EMPTY):
    output = {}
    if overflowType == CONST_VAROFLW:
        output[CONST_OFNVAR] = overFlown

    if overflowType == CONST_SCORRUPTION:
        output[CONST_OFNADDR] = CONST_LIMIT_ADDR

    if overflowType == CONST_INVALIDACC:
        output[CONST_OFNADDR] = overFlown

    if fnName == CONST_MOV:
        output[CONST_OPERATION] = fnName
    else:
        output[CONST_FNNAME] = fnName
        output[CONST_OFVAR] = nameVar #funcao de buffers recursivos

    output[CONST_VULN] = overflowType
    output[CONST_VULNFN] = vulnFnName
    output[CONST_ADDRESS] = instruction[CONST_ADDRESS]

    return output

def overflowAddrDetector(instruction, lastAddress, nameVar, vulnFnName, fnName):
    overflowerAddr = None
    overflwnVariables = {}

    lastAddress = parseAddress(lastAddress)
    if fnName != CONST_EMPTY:
        overflowerAddr = parseAddress(variablesProgram[vulnFnName][nameVar][CONST_ADDRESS])
        overflwnVariables = overflownVariables(lastAddress, nameVar, vulnFnName)
    else:
        overflowerAddr = parseAddress((instruction[CONST_ARGS][CONST_DEST]).split()[-1])

    alreadyInvalid = False
    print "last: " + lastAddress
    lastPLUSoneAddress = incrementAddress(lastAddress)
    while overflowerAddr != lastPLUSoneAddress:
        if overflowerAddr not in memory and not alreadyInvalid and overflowerAddr != CONST_LIMIT_ADDR:
            if instruction[CONST_OPERATION] == CONST_MOV:
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_MOV, overflowerAddr))
            else:
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, fnName, overflowerAddr))
            alreadyInvalid = True

        if overflowerAddr in overflwnVariables:
            alreadyInvalid = False
            outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_VAROFLW, fnName, overflwnVariables[overflowerAddr]))

        overflowerAddr = incrementAddress(overflowerAddr)


def checkOverflowType(instruction, nameVar, vulnFnName, fnName, lastAddress):
    lastAddress = parseAddress(lastAddress)

    print "Writed last address: " + lastAddress
    value = getCountOfAddress(lastAddress)

    if CONST_PLUS in lastAddress:
        if value >= 16:
            print "overflow vars, rbp, retAddr, SCORRUPTION"
            overflowAddrDetector(instruction, lastAddress, nameVar, vulnFnName, fnName)
            for i in range(len(vulnList)):
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

        elif value >= 8:
            print "overflow vars, rbp, retAddr"
            overflowAddrDetector(instruction, lastAddress, nameVar, vulnFnName, fnName)
            for i in range(len(vulnList)-1):
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

        elif value >= 0:
            print "overflow vars, rbp"
            overflowAddrDetector(instruction, lastAddress, nameVar, vulnFnName, fnName)
            for i in range(len(vulnList)-2):
                outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

    elif CONST_MINUS in lastAddress:
        print "overflow vars"
        overflowAddrDetector(instruction, lastAddress, nameVar, vulnFnName, fnName)

    else:
        print "nothing else"
        return

def inspectVulnerability(instruction, vulnFnName):
    callFnName = instruction[CONST_ARGS][CONST_FNNAME]

    if CONST_FGETS in callFnName:
        sizeOfInputInt = int(registersOfFunctions[CONST_ESI],0)
        fnName = CONST_FGETS
        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfDestInt = destVariable[CONST_BYTES]
        withEOF = True

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_GETS in callFnName:
        fnName = CONST_GETS
        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfInputInt = CONST_WRITE_EVERYTHNG - getCountOfAddress(destAddress) #the size to overFlow everything
        sizeOfDestInt = destVariable[CONST_BYTES]
        withEOF = False

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_READ in callFnName:
        fnName = CONST_READ
        sizeOfInputInt = int(registersOfFunctions[CONST_EDX],0)
        destAddress = registersOfFunctions[registersOrder[1]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfDestInt = destVariable[CONST_BYTES]
        withEOF = False

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_STRNCAT in callFnName:
        fnName = CONST_STRNCAT
        srcAddress = registersOfFunctions[registersOrder[1]]
        sizeOfSrcInt = int(registersOfFunctions[CONST_EDX], 0) + 1 #'\0'
        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfDestInt = destVariable[CONST_BYTES]

        endOfStringAddr = getAddrEOF(nameVar, vulnFnName)
        sizeOfStrInt = getSizeOfBuffer(destAddress) - 1 #free the '\0'
        withEOF = True
        srcBuffers = {}
        srcBuffers[srcAddress] = sizeOfSrcInt
        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcBuffers, sizeOfStrInt, endOfStringAddr)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_STRCAT in callFnName:
        fnName = CONST_STRCAT
        srcAddress = registersOfFunctions[registersOrder[1]]
        sizeOfSrcInt = getSizeOfBuffer(srcAddress)
        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfDestInt = destVariable[CONST_BYTES]

        endOfStringAddr = getAddrEOF(nameVar, vulnFnName)
        sizeOfStrInt = getSizeOfBuffer(destAddress)
        withEOF = True
        srcBuffers = {}
        srcBuffers[srcAddress] = sizeOfSrcInt
        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcBuffers, sizeOfStrInt, endOfStringAddr)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_STRNCPY in callFnName:
        fnName = CONST_STRNCPY
        srcAddress = registersOfFunctions[registersOrder[1]]
        sizeOfSrcInt = int(registersOfFunctions[CONST_EDX], 0)
        srcAddress = registersOfFunctions[registersOrder[1]]

        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfDestInt = destVariable[CONST_BYTES]
        withEOF = False
        srcBuffers = {}
        srcBuffers[srcAddress] = sizeOfSrcInt
        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcBuffers)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_STRCPY in callFnName:
        fnName = CONST_STRCPY
        srcAddress = registersOfFunctions[registersOrder[1]]
        sizeOfSrcInt = getSizeOfBuffer(srcAddress)

        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfDestInt = destVariable[CONST_BYTES]
        withEOF = True
        srcBuffers = {}
        srcBuffers[srcAddress] = sizeOfSrcInt
        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcBuffers)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_FSCANF in callFnName:
        fnName = CONST_FSCANF
        destAddress = registersOfFunctions[registersOrder[2]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfDestInt = destVariable[CONST_BYTES]
        sizeOfInputInt = CONST_WRITE_EVERYTHNG - getCountOfAddress(destAddress) #the size to overFlow everything
        withEOF = False
        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_SCANF in callFnName:
        fnName = CONST_SCANF
        destAddress = registersOfFunctions[registersOrder[1]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfDestInt = destVariable[CONST_BYTES]
        sizeOfInputInt = CONST_WRITE_EVERYTHNG - getCountOfAddress(destAddress) #the size to overFlow everything
        withEOF = False
        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_SNPRINTF in callFnName:
        #["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        fnName = CONST_SNPRINTF
        withEOF = True
        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfDestInt = destVariable[CONST_BYTES]
        firstSrc = registersOfFunctions[registersOrder[3]]
        sizeOfFirstSrc = getSizeOfBuffer(firstSrc)
        secondSrc = None
        if registersOrder[3] in registersOfFunctions:
            secondSrc = registersOfFunctions[registersOrder[4]]

        sizeOfInputInt = int(registersOfFunctions[CONST_ESI], 0)
        srcBuffers = {}
        srcBuffers[firstSrc] = sizeOfFirstSrc
        if secondSrc is not None:
            srcBuffers[secondSrc] = getSizeOfBuffer(secondSrc)

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt, srcBuffers)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_SPRINTF in callFnName:
        fnName = CONST_SPRINTF
        withEOF = True
        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
        sizeOfDestInt = destVariable[CONST_BYTES]
        firstSrc = registersOfFunctions[registersOrder[2]]
        sizeOfFirstSrc = getSizeOfBuffer(firstSrc)
        secondSrc = None
        if registersOrder[3] in registersOfFunctions:
            secondSrc = registersOfFunctions[registersOrder[3]]

        sizeOfInputInt = sizeOfFirstSrc
        srcBuffers = {}
        srcBuffers[firstSrc] = sizeOfFirstSrc
        if secondSrc is not None:
            sizeOfInputInt += getSizeOfBuffer(secondSrc)
            srcBuffers[secondSrc] = getSizeOfBuffer(secondSrc)

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt, srcBuffers)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    print "No Vulnerability at " + callFnName
    return False

def inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction):
    lastAddress = None

    if len(dangerousFunction.srcBuffers) == 0:
        lastAddress = writeToMemory(dangerousFunction.destAddress, dangerousFunction.sizeOfInputInt, CONST_TRASH, dangerousFunction.withEOF)
    else:
        if dangerousFunction.endOfStringAddr is None:
            lastAddress = dangerousFunction.destAddress
            leftOverSize = dangerousFunction.sizeOfInputInt
            for srcAddress in dangerousFunction.srcBuffers:
                srcSize = dangerousFunction.srcBuffers[srcAddress]
                if leftOverSize > srcSize:
                    leftOverSize -= srcSize
                else:
                    srcSize = leftOverSize
                lastAddress = writeToMemory(lastAddress, srcSize, srcAddress, dangerousFunction.withEOF)
        else:
            for srcAddress in dangerousFunction.srcBuffers:
                lastAddress = writeToMemory(dangerousFunction.endOfStringAddr, dangerousFunction.srcBuffers[srcAddress], srcAddress, dangerousFunction.withEOF)

    if dangerousFunction.sizeOfInputInt + dangerousFunction.sizeOfStrInt > dangerousFunction.sizeOfDestInt:
        print "Exists Variable Overflow: " + vulnFnName
        checkOverflowType(instruction, nameVar, vulnFnName, dangerousFunction.fnName, lastAddress)
        return True

    print "No Vulnerability at " + vulnFnName
    return False

def doRegisterOperation(instruction, vulnFnName):
    operation = instruction[CONST_OPERATION]
    dest = instruction[CONST_ARGS][CONST_DEST]
    value = instruction[CONST_ARGS][CONST_VALUE]

    if value in registersOfFunctions:
        value = registersOfFunctions[value]

    for spec in sizeSpecifications:
        if spec in dest:
            words = dest.split()
            size = sizeSpecifications[words[0]]
            destAddress = words[-1]
            withEOF = False
            valueMemory = value
            if valueMemory == CONST_NULL_CHAR:
                valueMemory = CONST_EOF
            else:
                valueMemory = CONST_TRASH

            nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
            lastAddress = writeToMemory(destAddress, size, valueMemory, withEOF)
            overflowAddrDetector(instruction, lastAddress, CONST_EMPTY, vulnFnName, CONST_EMPTY)

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
        if functionName in func:
            return True

    for fName in jsonProgram:
        if fName in functionName:
            checkFunction(jsonProgram[fName], fName)
            return False
    return False

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
    variablesProgram[fnName] = {}
    for var in function[CONST_VARIABLES]:
        nameVar = var[CONST_NAME]
        variablesProgram[fnName][nameVar] = var
    initializeMemory(function)

    instructions = function[CONST_INSTRUCTIONS]
    for instruction in instructions:
        operation = instruction[CONST_OPERATION]

        #verifying call function
        if operation == CONST_CALL_OPERATION:
            if checkOperationCall(instruction):
                inspectVulnerability(instruction, fnName)
            continue

        if operation in assemblyInstructions[CONST_BASIC]:
            doRegisterOperation(instruction, fnName)

    cleanRegisters()

def settingBasicName(fileName):
    return fileName[:19] + "outputs/" + fileName[19:-5] + ".myoutput.json"

def settingAdvancedName(fileName):
    return fileName[:22] + "outputs/" + fileName[22:-5] + ".myoutput.json"

#Main
if(len(sys.argv) < 2):
    print "No program received!"
    exit()

fileName = str(sys.argv[1])
with open(fileName) as json_data:
    jsonProgram = json.load(json_data)

checkFunction(jsonProgram[CONST_MAIN], CONST_MAIN)
print outputJSON
if "basic" in fileName:
    with open(settingBasicName(fileName), 'w') as outfile:
        json.dump(outputJSON, outfile)
if "advanced" in fileName:
    with open(settingAdvancedName(fileName), 'w') as outfile:
        json.dump(outputJSON, outfile)
