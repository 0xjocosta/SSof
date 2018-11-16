import glob
import json

outputs = glob.glob("*.output.json")
myoutputs = glob.glob("*.myoutput.json")

jsonMy = {}
jsonOut = {}

for output in outputs:
    for myoutput in myoutputs:
        if myoutput[0:5] == output[0:5]:
            with open(myoutput) as json_data:
                jsonMy = json.load(json_data)
            with open(output) as json_dat:
                jsonOut = json.load(json_dat)

            """origJson = jsonMy
            for my in jsonMy:
                for out in jsonOut:
                    #print "MY: " + str(my.keys())
                    #print "OUT: " + str(out.keys())
                    for myKey in my.keys():
                        if myKey in jsonOut:
                            #print "out: " + out[myKey]
                            if my[myKey] != out[myKey]:
                                #print "AAAAAAAAAAAAAAAAA"
                                break

                    if my in origJson:
                        #print my
                        origJson.remove(my)


            if len(origJson) > 0:
                print "My " + myoutput
                print origJson
                print '\n'"""

            if jsonMy != jsonOut:
                print "My " + myoutput
                #print jsonMy
                #print "\n"
                print "Out " + output
                #print jsonOut
                #print "\n\n\n"
