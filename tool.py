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
dangerousFunctions = ("<fgets@plt>", "<strcpy@plt>", "<strcat@plt>", "<sprintf@plt>", "<fscanf@plt>", "<scanf@plt>", "<gets@plt>", "<strncpy@plt>", "<strncat@plt>", "<snprintf@plt>", "<read@plt>")
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

class DangerousFunction(object):
    """docstring for DangerousFunction."""
    def __init__(self, fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt=None, srcAddress=None, sizeOfStrInt=0, endOfStringAddr=None):
        super(DangerousFunction, self).__init__()
        self.fnName = fnName
        self.destAddress = destAddress
        self.sizeOfDestInt = sizeOfDestInt
        self.withEOF = withEOF
        self.srcAddress = srcAddress
        self.sizeOfSrcInt = sizeOfSrcInt
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
        if addr not in memory and value != CONST_ZERO:
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

def getNameAndVariable(addr):
    destVariable = {}
    nameVar = ""
    for var in variablesProgram:
        variable = variablesProgram[var]
        if variable[CONST_ADDRESS] in addr:
            destVariable = variable
            nameVar = var
    return nameVar, destVariable

def overflownVariables(addrEOF, nameVar):
    overflwnVariables = {}

    overflowerAddr = parseAddress(variablesProgram[nameVar][CONST_ADDRESS])
    intOverflowerAddr = getCountOfAddress(overflowerAddr)

    addrEOF = parseAddress(addrEOF)
    intEOF = getCountOfAddress(addrEOF)
    for var in variablesProgram:
        addrVariable = variablesProgram[var][CONST_ADDRESS]
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

    output[CONST_VULN] = overflowType
    output[CONST_VULNFN] = vulnFnName
    output[CONST_ADDRESS] = instruction[CONST_ADDRESS]
    output[CONST_FNNAME] = fnName
    output[CONST_OFVAR] = nameVar #funcao de buffers recursivos
    return output

def overflowAddrDetector(instruction, lastAddress, nameVar, vulnFnName, fnName):
    overflowerAddr = parseAddress(variablesProgram[nameVar][CONST_ADDRESS])
    lastAddress = parseAddress(lastAddress)
    lastAddress = incrementAddress(lastAddress)

    overflwnVariables = overflownVariables(lastAddress, nameVar)

    alreadyInvalid = False
    while overflowerAddr != lastAddress:
        print overflowerAddr
        if overflowerAddr not in memory and not alreadyInvalid and overflowerAddr != CONST_LIMIT_ADDR:
            outputJSON.append(outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, fnName, overflowerAddr))
            alreadyInvalid = True

        if overflowerAddr in overflwnVariables:
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
        nameVar, destVariable = getNameAndVariable(destAddress)
        sizeOfDestInt = destVariable[CONST_BYTES]
        withEOF = True

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_GETS in callFnName:
        fnName = CONST_GETS
        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress)
        sizeOfInputInt = CONST_WRITE_EVERYTHNG - getCountOfAddress(destAddress) #the size to overFlow everything
        sizeOfDestInt = destVariable[CONST_BYTES]
        withEOF = False

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_READ in callFnName:
        fnName = CONST_READ
        sizeOfInputInt = int(registersOfFunctions[CONST_EDX],0)
        destAddress = registersOfFunctions[registersOrder[1]]
        nameVar, destVariable = getNameAndVariable(destAddress)
        sizeOfDestInt = destVariable[CONST_BYTES]
        withEOF = False

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_STRNCAT in callFnName:
        fnName = CONST_STRNCAT
        srcAddress = registersOfFunctions[registersOrder[1]]
        sizeOfSrcInt = int(registersOfFunctions[CONST_EDX], 0) + 1 #'\0'
        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress)
        sizeOfDestInt = destVariable[CONST_BYTES]

        endOfStringAddr = getAddrEOF(nameVar)
        sizeOfStrInt = getSizeOfBuffer(destAddress) - 1 #free the '\0'
        withEOF = True
        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcAddress, sizeOfStrInt, endOfStringAddr)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_STRCAT in callFnName:
        fnName = CONST_STRCAT
        srcAddress = registersOfFunctions[registersOrder[1]]
        sizeOfSrcInt = getSizeOfBuffer(srcAddress)
        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress)
        sizeOfDestInt = destVariable[CONST_BYTES]

        endOfStringAddr = getAddrEOF(nameVar)
        sizeOfStrInt = getSizeOfBuffer(destAddress)
        withEOF = True

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcAddress, sizeOfStrInt, endOfStringAddr)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_STRNCPY in callFnName:
        fnName = CONST_STRNCPY
        srcAddress = registersOfFunctions[registersOrder[1]]
        sizeOfSrcInt = int(registersOfFunctions[CONST_EDX], 0)
        srcAddress = registersOfFunctions[registersOrder[1]]

        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress)
        sizeOfDestInt = destVariable[CONST_BYTES]
        withEOF = False

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcAddress)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_STRCPY in callFnName:
        fnName = CONST_STRCPY
        srcAddress = registersOfFunctions[registersOrder[1]]
        sizeOfSrcInt = getSizeOfBuffer(srcAddress)

        destAddress = registersOfFunctions[registersOrder[0]]
        nameVar, destVariable = getNameAndVariable(destAddress)
        sizeOfDestInt = destVariable[CONST_BYTES]
        withEOF = True

        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcAddress)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_SCANF in callFnName:
        fnName = CONST_SCANF
        destAddress = registersOfFunctions[registersOrder[1]]
        nameVar, destVariable = getNameAndVariable(destAddress)
        sizeOfDestInt = destVariable[CONST_BYTES]
        sizeOfInputInt = CONST_WRITE_EVERYTHNG - getCountOfAddress(destAddress) #the size to overFlow everything
        withEOF = False
        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    if CONST_FSCANF in callFnName:
        fnName = CONST_FSCANF
        destAddress = registersOfFunctions[registersOrder[2]]
        nameVar, destVariable = getNameAndVariable(destAddress)
        sizeOfDestInt = destVariable[CONST_BYTES]
        sizeOfInputInt = CONST_WRITE_EVERYTHNG - getCountOfAddress(destAddress) #the size to overFlow everything
        withEOF = False
        dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
        return inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

    print "No Vulnerability at " + callFnName
    return False

def inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction):
    lastAddress = None

    if dangerousFunction.srcAddress is None:
        lastAddress = writeToMemory(dangerousFunction.destAddress, dangerousFunction.sizeOfSrcInt, CONST_TRASH, dangerousFunction.withEOF)
    else:
        if dangerousFunction.endOfStringAddr is None:
            lastAddress = writeToMemory(dangerousFunction.destAddress, dangerousFunction.sizeOfSrcInt, dangerousFunction.srcAddress, dangerousFunction.withEOF)
        else:
            lastAddress = writeToMemory(dangerousFunction.endOfStringAddr, dangerousFunction.sizeOfSrcInt, dangerousFunction.srcAddress, dangerousFunction.withEOF)

    if dangerousFunction.sizeOfSrcInt + dangerousFunction.sizeOfStrInt > dangerousFunction.sizeOfDestInt:
        print "Exists Variable Overflow: " + vulnFnName
        checkOverflowType(instruction, nameVar, vulnFnName, dangerousFunction.fnName, lastAddress)
        return True

    print "No Vulnerability at " + vulnFnName
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
    for var in function[CONST_VARIABLES]:
        nameVar = var[CONST_NAME]
        variablesProgram[nameVar] = var
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
            doRegisterOperation(instruction)

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
