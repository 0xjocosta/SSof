import sys
import json

#Static Names
CONST_N_INSTRUCTIONS = "Ninstructions"
CONST_VARIABLES = "variables"
CONST_INSTRUCTIONS = "instructions"
CONST_BASIC = "basic"
CONST_ADVANCED= "advanced"
CONST_OPERATION = "op"
CONST_POS = "pos"
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

#advanced instructions
CONST_JMP = "jmp"
CONST_JNE = "jne"
CONST_JE = "je"
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
CONST_BRANCH = "branch"

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

class Branch(object):

    def __init__(self, nameBranch, memory={}, registersOfFunctions={}, variablesProgram={}):
        super(Branch, self).__init__()
        self.nameBranch = nameBranch
        self.memory = memory
        self.registersOfFunctions = registersOfFunctions
        self.variablesProgram = variablesProgram

    def run(self, nameFunction, position):
        self.checkFunction(jsonProgram[nameFunction], nameFunction, position)

    def printMemory(self):
        print "---------Memory---------"
        for addr in sorted (self.memory.keys()):
            print addr + "-> " + self.memory[addr]

        print "---------Memory---------"

    def printRegisters(self):
        print "-------------REGISTERS: -----------"
        for register in self.registersOfFunctions:
            print register + ": " + self.registersOfFunctions[register]
        print "-------------REGISTERS: -----------"

    def parseAddress(self, address):
        if "[" in address:
            return address[1:-1]
        else:
            return address

    def incrementAddress(self, address):
        address = self.parseAddress(address)
        count = int(address[3:], 0) + 1
        if count >= 0:
            address = address[0:3] + CONST_PLUS + hex(count)
        else:
            address = address[0:3] + hex(count)
        return address

    def decrementAddress(self, address):
        address = self.parseAddress(address)

        count = int(address[3:], 0) - 1
        if count >= 0:
            address = address[0:3] + CONST_PLUS + hex(count)
        else:
            address = address[0:3] + hex(count)
        return address

    def getCountOfAddress(self, address):
        address = self.parseAddress(address)
        return int(address[3:], 0)

    def writeToAddress(self, address ,value):
        self.memory[address] = value

    def writeToMemory(self, addr, size, value, withEOF):
        addr = self.parseAddress(addr)
        print "first addr: " + addr
        print "size: " + str(size)
        count = self.getCountOfAddress(addr)
        maxSize = count + size - 1
        while(count != maxSize):
            #invalid address
            if addr not in self.memory and value != CONST_ZERO:
                addr = self.incrementAddress(addr)
                count += 1
                continue

            #parse meaningful values
            if value != CONST_TRASH and value != CONST_ZERO and value != CONST_EOF:
                value = self.parseAddress(value)
                self.writeToAddress(addr, self.memory[value])
                value = self.incrementAddress(value)
            else:
                self.writeToAddress(addr, value)

            addr = self.incrementAddress(addr)
            count += 1

            if addr == CONST_LIMIT_ADDR:
                return addr

        #invalid address
        if addr not in self.memory and value != CONST_ZERO:
            if value == CONST_TRASH:
                return addr
            if value == CONST_EOF:
                self.writeToAddress(addr, CONST_EOF)
                return addr
            return addr

        if withEOF:
            self.writeToAddress(addr, CONST_EOF)
            return addr
        else:
            #Copy buffer to another buffer
            if value != CONST_TRASH and value != CONST_ZERO and value != CONST_EOF:
                self.writeToAddress(addr, self.memory[value])
                return addr
            #write to buffer
            else:
                self.writeToAddress(addr, value)
                return addr

    def getSizeOfBuffer(self, address):
        address = self.parseAddress(address)
        size = 1
        while True:
            if address == CONST_LIMIT_ADDR:
                return size
            value = self.memory[address]
            if value == CONST_EOF:
                return size

            address = self.incrementAddress(address)
            size += 1

    def getAddrEOF(self, varName, fnName):
        address = self.variablesProgram[fnName][varName][CONST_ADDRESS]
        address = self.parseAddress(address)
        while True:
            if address == CONST_LIMIT_ADDR:
                return address
            value = self.memory[address]
            if value == CONST_EOF:
                return address

            address = self.incrementAddress(address)

    def getMemoryAddrs(self, firstAddr, lastAddress):
        addresses = {}

        firstAddr = self.parseAddress(firstAddr)
        lastAddress = self.parseAddress(lastAddress)
        while firstAddr != lastAddress:
            addresses[firstAddr] = self.memory[firstAddr]
            firstAddr = self.incrementAddress(firstAddr)

        self.memory[firstAddr] = self.memory[firstAddr]
        return addresses

    def getNameAndVariable(self, addr, fnName):
        destVariable = {}
        nameVar = CONST_EMPTY
        for var in self.variablesProgram[fnName]:
            variable = self.variablesProgram[fnName][var]
            if variable[CONST_ADDRESS] in addr:
                destVariable = variable
                nameVar = var
        return nameVar, destVariable

    def overflownVariables(self, addrEOF, nameVar, fnName):
        overflwnVariables = {}

        overflowerAddr = self.parseAddress(self.variablesProgram[fnName][nameVar][CONST_ADDRESS])
        intOverflowerAddr = self.getCountOfAddress(overflowerAddr)

        addrEOF = self.parseAddress(addrEOF)
        intEOF = self.getCountOfAddress(addrEOF)
        for var in self.variablesProgram[fnName]:
            addrVariable = self.variablesProgram[fnName][var][CONST_ADDRESS]
            addrVariable = self.parseAddress(addrVariable)
            intAddrVariable = self.getCountOfAddress(addrVariable)
            if intEOF >= intAddrVariable > intOverflowerAddr and addrVariable != overflowerAddr:
                overflwnVariables[addrVariable] = var

        return overflwnVariables

    def outputOverflow(self, instruction, nameVar, vulnFnName, overflowType, fnName, overFlown = CONST_EMPTY):
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

    def overflowAddrDetector(self, instruction, lastAddress, nameVar, vulnFnName, fnName):
        overflowerAddr = None
        overflwnVariables = {}

        lastAddress = self.parseAddress(lastAddress)
        if fnName != CONST_EMPTY:
            overflowerAddr = self.parseAddress(self.variablesProgram[vulnFnName][nameVar][CONST_ADDRESS])
            overflwnVariables = self.overflownVariables(lastAddress, nameVar, vulnFnName)
        else:
            overflowerAddr = self.parseAddress((instruction[CONST_ARGS][CONST_DEST]).split()[-1])

        alreadyInvalid = False
        print "last: " + lastAddress
        lastPLUSoneAddress = self.incrementAddress(lastAddress)
        while overflowerAddr != lastPLUSoneAddress:
            if overflowerAddr not in self.memory and not alreadyInvalid and overflowerAddr != CONST_LIMIT_ADDR:
                if instruction[CONST_OPERATION] == CONST_MOV:
                    outputJSON.append(self.outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, CONST_MOV, overflowerAddr))
                else:
                    outputJSON.append(self.outputOverflow(instruction, nameVar, vulnFnName, CONST_INVALIDACC, fnName, overflowerAddr))
                alreadyInvalid = True

            if overflowerAddr in overflwnVariables:
                alreadyInvalid = False
                outputJSON.append(self.outputOverflow(instruction, nameVar, vulnFnName, CONST_VAROFLW, fnName, overflwnVariables[overflowerAddr]))

            overflowerAddr = self.incrementAddress(overflowerAddr)


    def checkOverflowType(self, instruction, nameVar, vulnFnName, fnName, lastAddress):
        lastAddress = self.parseAddress(lastAddress)

        print "Writed last address: " + lastAddress
        value = self.getCountOfAddress(lastAddress)

        if CONST_PLUS in lastAddress:
            if value >= 16:
                print "overflow vars, rbp, retAddr, SCORRUPTION"
                self.overflowAddrDetector(instruction, lastAddress, nameVar, vulnFnName, fnName)
                for i in range(len(vulnList)):
                    outputJSON.append(self.outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

            elif value >= 8:
                print "overflow vars, rbp, retAddr"
                self.overflowAddrDetector(instruction, lastAddress, nameVar, vulnFnName, fnName)
                for i in range(len(vulnList)-1):
                    outputJSON.append(self.outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

            elif value >= 0:
                print "overflow vars, rbp"
                self.overflowAddrDetector(instruction, lastAddress, nameVar, vulnFnName, fnName)
                for i in range(len(vulnList)-2):
                    outputJSON.append(self.outputOverflow(instruction, nameVar, vulnFnName, vulnList[i], fnName))

        elif CONST_MINUS in lastAddress:
            print "overflow vars"
            self.overflowAddrDetector(instruction, lastAddress, nameVar, vulnFnName, fnName)

        else:
            print "nothing else"
            return

    def inspectVulnerability(self, instruction, vulnFnName):
        callFnName = instruction[CONST_ARGS][CONST_FNNAME]

        if CONST_FGETS in callFnName:
            sizeOfInputInt = int(self.registersOfFunctions[CONST_ESI],0)
            fnName = CONST_FGETS
            destAddress = self.registersOfFunctions[registersOrder[0]]
            nameVar, destVariable = self.getNameAndVariable(destAddress, vulnFnName)
            sizeOfDestInt = destVariable[CONST_BYTES]
            withEOF = True

            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        if CONST_GETS in callFnName:
            fnName = CONST_GETS
            destAddress = self.registersOfFunctions[registersOrder[0]]
            nameVar, destVariable = self.getNameAndVariable(destAddress, vulnFnName)
            sizeOfInputInt = CONST_WRITE_EVERYTHNG - self.getCountOfAddress(destAddress) #the size to overFlow everything
            sizeOfDestInt = destVariable[CONST_BYTES]
            withEOF = False

            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        if CONST_READ in callFnName:
            fnName = CONST_READ
            sizeOfInputInt = int(self.registersOfFunctions[CONST_EDX],0)
            destAddress = self.registersOfFunctions[registersOrder[1]]
            nameVar, destVariable = self.getNameAndVariable(destAddress, vulnFnName)
            sizeOfDestInt = destVariable[CONST_BYTES]
            withEOF = False

            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        if CONST_STRNCAT in callFnName:
            fnName = CONST_STRNCAT
            srcAddress = self.registersOfFunctions[registersOrder[1]]
            sizeOfSrcInt = int(self.registersOfFunctions[CONST_EDX], 0) + 1 #'\0'
            destAddress = self.registersOfFunctions[registersOrder[0]]
            nameVar, destVariable = self.getNameAndVariable(destAddress, vulnFnName)
            sizeOfDestInt = destVariable[CONST_BYTES]

            endOfStringAddr = self.getAddrEOF(nameVar, vulnFnName)
            sizeOfStrInt = self.getSizeOfBuffer(destAddress) - 1 #free the '\0'
            withEOF = True
            srcBuffers = {}
            srcBuffers[srcAddress] = sizeOfSrcInt
            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcBuffers, sizeOfStrInt, endOfStringAddr)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        if CONST_STRCAT in callFnName:
            fnName = CONST_STRCAT
            srcAddress = self.registersOfFunctions[registersOrder[1]]
            sizeOfSrcInt = self.getSizeOfBuffer(srcAddress)
            destAddress = self.registersOfFunctions[registersOrder[0]]
            nameVar, destVariable = getNameAndVariable(destAddress, vulnFnName)
            sizeOfDestInt = destVariable[CONST_BYTES]

            endOfStringAddr = self.getAddrEOF(nameVar, vulnFnName)
            sizeOfStrInt = self.getSizeOfBuffer(destAddress)
            withEOF = True
            srcBuffers = {}
            srcBuffers[srcAddress] = sizeOfSrcInt
            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcBuffers, sizeOfStrInt, endOfStringAddr)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        if CONST_STRNCPY in callFnName:
            fnName = CONST_STRNCPY
            srcAddress = self.registersOfFunctions[registersOrder[1]]
            sizeOfSrcInt = int(self.registersOfFunctions[CONST_EDX], 0)
            srcAddress = self.registersOfFunctions[registersOrder[1]]

            destAddress = self.registersOfFunctions[registersOrder[0]]
            nameVar, destVariable = self.getNameAndVariable(destAddress, vulnFnName)
            sizeOfDestInt = destVariable[CONST_BYTES]
            withEOF = False
            srcBuffers = {}
            srcBuffers[srcAddress] = sizeOfSrcInt
            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcBuffers)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        if CONST_STRCPY in callFnName:
            fnName = CONST_STRCPY
            srcAddress = self.registersOfFunctions[registersOrder[1]]
            sizeOfSrcInt = self.getSizeOfBuffer(srcAddress)

            destAddress = self.registersOfFunctions[registersOrder[0]]
            nameVar, destVariable = self.getNameAndVariable(destAddress, vulnFnName)
            sizeOfDestInt = destVariable[CONST_BYTES]
            withEOF = True
            srcBuffers = {}
            srcBuffers[srcAddress] = sizeOfSrcInt
            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfSrcInt, srcBuffers)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        if CONST_FSCANF in callFnName:
            fnName = CONST_FSCANF
            destAddress = self.registersOfFunctions[registersOrder[2]]
            nameVar, destVariable = self.getNameAndVariable(destAddress, vulnFnName)
            sizeOfDestInt = destVariable[CONST_BYTES]
            sizeOfInputInt = CONST_WRITE_EVERYTHNG - self.getCountOfAddress(destAddress) #the size to overFlow everything
            withEOF = False
            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        if CONST_SCANF in callFnName:
            fnName = CONST_SCANF
            destAddress = self.registersOfFunctions[registersOrder[1]]
            nameVar, destVariable = self.getNameAndVariable(destAddress, vulnFnName)
            sizeOfDestInt = destVariable[CONST_BYTES]
            sizeOfInputInt = CONST_WRITE_EVERYTHNG - self.getCountOfAddress(destAddress) #the size to overFlow everything
            withEOF = False
            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        if CONST_SNPRINTF in callFnName:
            #["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            fnName = CONST_SNPRINTF
            withEOF = True
            destAddress = self.registersOfFunctions[registersOrder[0]]
            nameVar, destVariable = self.getNameAndVariable(destAddress, vulnFnName)
            sizeOfDestInt = destVariable[CONST_BYTES]
            firstSrc = self.registersOfFunctions[registersOrder[3]]
            sizeOfFirstSrc = self.getSizeOfBuffer(firstSrc)
            secondSrc = None
            if registersOrder[3] in self.registersOfFunctions:
                secondSrc = self.registersOfFunctions[registersOrder[4]]

            sizeOfInputInt = int(self.registersOfFunctions[CONST_ESI], 0)
            srcBuffers = {}
            srcBuffers[firstSrc] = sizeOfFirstSrc
            if secondSrc is not None:
                srcBuffers[secondSrc] = self.getSizeOfBuffer(secondSrc)

            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt, srcBuffers)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        if CONST_SPRINTF in callFnName:
            fnName = CONST_SPRINTF
            withEOF = True
            destAddress = self.registersOfFunctions[registersOrder[0]]
            nameVar, destVariable =self. getNameAndVariable(destAddress, vulnFnName)
            sizeOfDestInt = destVariable[CONST_BYTES]
            firstSrc = self.registersOfFunctions[registersOrder[2]]
            sizeOfFirstSrc = self.getSizeOfBuffer(firstSrc)
            secondSrc = None
            if registersOrder[3] in self.registersOfFunctions:
                secondSrc = self.registersOfFunctions[registersOrder[3]]

            sizeOfInputInt = sizeOfFirstSrc
            srcBuffers = {}
            srcBuffers[firstSrc] = sizeOfFirstSrc
            if secondSrc is not None:
                sizeOfInputInt += self.getSizeOfBuffer(secondSrc)
                srcBuffers[secondSrc] = self.getSizeOfBuffer(secondSrc)

            dangerousFunction = DangerousFunction(fnName, destAddress, sizeOfDestInt, withEOF, sizeOfInputInt, srcBuffers)
            return self.inspectDangerousFunction(instruction, nameVar, vulnFnName, dangerousFunction)

        print "No Vulnerability at " + callFnName
        return False

    def inspectDangerousFunction(self, instruction, nameVar, vulnFnName, dangerousFunction):
        lastAddress = None

        if len(dangerousFunction.srcBuffers) == 0:
            lastAddress = self.writeToMemory(dangerousFunction.destAddress, dangerousFunction.sizeOfInputInt, CONST_TRASH, dangerousFunction.withEOF)
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
                    lastAddress = self.writeToMemory(lastAddress, srcSize, srcAddress, dangerousFunction.withEOF)
            else:
                for srcAddress in dangerousFunction.srcBuffers:
                    lastAddress = self.writeToMemory(dangerousFunction.endOfStringAddr, dangerousFunction.srcBuffers[srcAddress], srcAddress, dangerousFunction.withEOF)

        if dangerousFunction.sizeOfInputInt + dangerousFunction.sizeOfStrInt > dangerousFunction.sizeOfDestInt:
            print "Exists Variable Overflow: " + vulnFnName
            self.checkOverflowType(instruction, nameVar, vulnFnName, dangerousFunction.fnName, lastAddress)
            return True

        print "No Vulnerability at " + vulnFnName
        return False

    def doAdvancedOperations(self, instruction, vulnFnName):
        operation = instruction[CONST_OPERATION]
        if operation == CONST_JMP:
            destAddr = instruction[CONST_ARGS][CONST_ADDRESS]
            print destAddr
            instruction = self.getInstructionByAddress(vulnFnName, destAddr)
            return instruction[CONST_POS]
        elif operation == CONST_JNE or operation == CONST_JE:
            destAddr = instruction[CONST_ARGS][CONST_ADDRESS]
            print destAddr
            instruction = self.getInstructionByAddress(vulnFnName, destAddr)
            branchName = CONST_BRANCH + str(COUNTER)
            branch = Branch(self.nameBranch, self.memory, self.registersOfFunctions, self.variablesProgram)
            branch.run(vulnFnName, instruction[CONST_POS])
            return -1
        return -1

    def doRegisterOperation(self, instruction, vulnFnName):
        operation = instruction[CONST_OPERATION]
        dest = instruction[CONST_ARGS][CONST_DEST]
        value = instruction[CONST_ARGS][CONST_VALUE]

        if value in self.registersOfFunctions:
            value = self.registersOfFunctions[value]

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

                nameVar, destVariable =self.getNameAndVariable(destAddress, vulnFnName)
                lastAddress = self.writeToMemory(destAddress, size, valueMemory, withEOF)
                self.overflowAddrDetector(instruction, lastAddress, CONST_EMPTY, vulnFnName, CONST_EMPTY)

        if operation in registerOperations:
            if dest not in self.registersOfFunctions:
                self.registersOfFunctions[dest] = registerOperations[operation] + value
            else:
                self.registersOfFunctions[dest] += registerOperations[operation] + value
        else:
            self.registersOfFunctions[dest] = value

    def checkOperationCall(self, instruction):
        functionName = instruction[CONST_ARGS][CONST_FNNAME]
        for func in dangerousFunctions:
            if functionName in func:
                return True

        for fName in jsonProgram:
            if fName in functionName:
                position = 0
                self.checkFunction(jsonProgram[fName], fName, position)
                return False
        return False

    def cleanRegisters(self):
        for register in self.registersOfFunctions.keys():
            if register not in registers:
                del self.registersOfFunctions[register]

    def initializeMemory(self, function):
        dic = {}

        for variable in function[CONST_VARIABLES]:
            size = variable[CONST_BYTES]
            address = variable[CONST_ADDRESS]
            dic[address] = size

        self.writeToMemory(CONST_RBP, 16, CONST_ZERO, False)

        for address in sorted (dic.keys()):
            self.writeToMemory(address, dic[address], CONST_ZERO, True)

    def checkFunction(self, function, fnName, position):
        nInstructions = function[CONST_N_INSTRUCTIONS]

        self.variablesProgram[fnName] = {}
        for var in function[CONST_VARIABLES]:
            nameVar = var[CONST_NAME]
            self.variablesProgram[fnName][nameVar] = var
        self.initializeMemory(function)

        instructions = function[CONST_INSTRUCTIONS]
        print "N instructions: " + str(nInstructions)

        while position < nInstructions:
            if self.nameBranch == (CONST_BRANCH + str(0)):
                print "position: " + str(position)
            instruction = self.getInstructionByPosition(fnName, position)
            operation = instruction[CONST_OPERATION]

            #verifying call function
            if operation == CONST_CALL_OPERATION:
                if self.checkOperationCall(instruction):
                    self.inspectVulnerability(instruction, fnName)
                position += 1
                continue

            if operation in assemblyInstructions[CONST_BASIC]:
                self.doRegisterOperation(instruction, fnName)

            if operation in assemblyInstructions[CONST_ADVANCED]:
                pos = self.doAdvancedOperations(instruction, fnName)
                if pos != -1:
                    position = pos
                    continue

            position += 1
        self.cleanRegisters()

    def getInstructionByPosition(self, fnName, position):
        for instruction in jsonProgram[fnName][CONST_INSTRUCTIONS]:
            if instruction[CONST_POS] == position:
                return instruction
        return {}

    def getInstructionByAddress(self, fnName, address):
        for instruction in jsonProgram[fnName][CONST_INSTRUCTIONS]:
            if instruction[CONST_ADDRESS] == address:
                return instruction
        return {}



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

COUNTER = 0
branch = CONST_BRANCH + str(COUNTER)
COUNTER += 1
position = 0
branchMain = Branch(branch)

branchMain.run(CONST_MAIN, position)



#checkFunction(jsonProgram[CONST_MAIN], CONST_MAIN, position, branch)
print outputJSON
if "basic" in fileName:
    with open(settingBasicName(fileName), 'w') as outfile:
        json.dump(outputJSON, outfile)
if "advanced" in fileName:
    with open(settingAdvancedName(fileName), 'w') as outfile:
        json.dump(outputJSON, outfile)
