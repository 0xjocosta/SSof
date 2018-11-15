import glob
import json

outputs = glob.glob("*.output.json")
myoutputs = glob.glob("*.myoutput.json")

jsonMy = {}
jsonOut = {}

for output in outputs:
    for myoutput in myoutputs:
        if myoutput[0:3] == output[0:3]:
            with open(myoutput) as json_data:
                jsonMy = json.load(json_data)
            with open(output) as json_dat:
                jsonOut = json.load(json_dat)

            if jsonMy != jsonOut:
                print "My " + myoutput
                """print jsonMy
                print "\n"
                print "Out " + output
                print jsonOut
                print "\n\n\n"""
