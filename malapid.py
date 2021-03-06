import argparse
import json
import rust_strings
from tabulate import tabulate

def main():

    # Initialize argparser
    parser = argparse.ArgumentParser(description="MalAPID finds suspicious strings and maps them to MITRE ATT&CK Techniques", epilog="Credits to mrd0x and https://malapi.io for the data.")
    parser.add_argument("-s", "--strings", action="store_true", help="Output all strings found")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase verbosity")
    parser.add_argument("-o", "--out-file", help="Save the output to a file")
    parser.add_argument("file", help="Input PE file to get strings data or text file with strings data already in it")
    args = vars(parser.parse_args()) # convert to dictionary

    strings = getStrings(args["file"])

    if args["strings"]:
        allStrings = strings
    else:
        allStrings = False

    susFunctionsFound, malapi_content = getWindowsSusFunctions(strings)
    outputResults(susFunctionsFound, malapi_content, in_file=args["file"], allStrings=allStrings, verbose=args["verbose"], out_file=args["out_file"])
    

def getStrings(file):

    # Returns a list of extracted strings from a binary file or text file

    if checkIfTextFile(file):
        return readStrings(file)
    else:
        return extractStrings(file)

def checkIfTextFile(file):

    # Returns if True if the inputted file is a text file

    extension = file.split(".")[-1]

    if extension == "txt":
        return True
    else:
        return False

def readStrings(file):

    # Read strings if user supplies a text file with strings already pulled

    f = open(file, "r")
    strings = []

    # Convert the file data to a list
    filedata = f.readlines()

    # Remove "\n"
    for string in filedata:
        string = string.strip()
        strings.append(string)

    f.close()

    return strings

def extractStrings(file):

    # Returns a list of extracted strings from a binary file

    # Returns a tuple containing (Strings, Offset) ex. ('InternetOpenUrlA', 179358)
    strings = rust_strings.strings(file_path=file, min_length=4)
    stringsWithoutOffset = []

    # Loops through the tuples and returns only the srtings
    for dataPair in strings:
        stringsWithoutOffset.append(dataPair[0])

    return stringsWithoutOffset

def getWindowsSusFunctions(strings):

    # Filters through strings data and returns a list of mostly
    # Windows Functions that exist on MalAPI.io

    # Load the data from MalAPI.io. Data as of 05/12/2022
    f = open('malapi_content.json')
    malapi_content = json.load(f)
    f.close()

    allWindowsSusFunctions = malapi_content.keys()
    discoveredWindowsFunctions = []

    for string in strings:

        try:
            firstLetter = string[0]
            stringLength = len(string)

            # The first letter of each Windows function is capital
            # and those on MalAPI.io are between 4 and 32 characters
            if firstLetter.isupper() and 4 <= stringLength <= 32:
                if string in allWindowsSusFunctions:
                    if string not in discoveredWindowsFunctions:
                        discoveredWindowsFunctions.append(string)
        except:
            continue

    return discoveredWindowsFunctions, malapi_content

def outputResults(susFunctionsFound, malapi_content, in_file, allStrings, verbose, out_file):

    try:
        f = open(out_file, "w")
    except:
        if out_file != None:
            print("Unable to save output to a file!")
        f = None

    print(" __  __       _    _    ____ ___ ____", file=f)
    print("|  \/  | __ _| |  / \  |  _ \_ _|  _ \ ", file=f)
    print("| |\/| |/ _` | | / _ \ | |_) | || | | |", file=f)
    print("| |  | | (_| | |/ ___ \|  __/| || |_| |", file=f)
    print("|_|  |_|\__,_|_/_/   \_\_|  |___|____/", file=f)

    print("\n+++++++++++++++++ Analysis of " + in_file + " +++++++++++++++++\n", file=f)

    # Create table for attack capabilities
    capabilitiesTable = []
    capabilitiesHeaders = ["Attack Capabilties"]

    # Create table for the suspicious functions found
    susFunctionsTable = []
    if verbose == True:
        susFunctionsHeaders = ["Suspicious Function", "Desciption", "Library", "Associated Attacks", "Documentation"]
    else:
        susFunctionsHeaders = ["Suspicious Function", "Desciption"]

    if len(susFunctionsFound) == 0:
        print("+++++++++++++++++++++++++++++++", file=f)
        print("No suspicious functions found!", file=f)
        print("+++++++++++++++++++++++++++++++", file=f)
    else:
        for func in susFunctionsFound:

            # Get unique values for associated_attacks
            associatedAttacks = malapi_content[func]["associated_attacks"]
            for attack in associatedAttacks:
                attack = [attack]
                if attack not in capabilitiesTable:
                    capabilitiesTable.append(attack)

            # Add the data from malapi_content to the susFunctionsTable
            susFunctionsContent = []
            susFunctionsContent.append(func)
            susFunctionsContent.append(malapi_content[func]["desciption"])
            if verbose == True:
                susFunctionsContent.append(malapi_content[func]["library"])
                susFunctionsContent.append(malapi_content[func]["associated_attacks"])
                susFunctionsContent.append(malapi_content[func]["documentation"])
            susFunctionsTable.append(susFunctionsContent)

        print(tabulate(capabilitiesTable, headers=capabilitiesHeaders, tablefmt="psql"), file=f)
        print(tabulate(susFunctionsTable, headers=susFunctionsHeaders, tablefmt="psql"), file=f)

    # Create table for all strings of the file if -s used
    if allStrings != False:
        allStringsTable = []
        for string in allStrings:
            allStringsTable.append([string])
        print(tabulate(allStringsTable, headers=["All Strings"], tablefmt="psql"), file=f)

    print("\nCredits to mrd0x and https://malapi.io for the data.", file=f)

main()