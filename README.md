# MalAPID
 MalAPID finds suspicious strings of binaries and maps them to MITRE ATT&CK Techniques
 The data used was pulled from https://malapi.io/.
# Install Dependencies
MalAPID uses rust_strings to extract strings and tabulate formats the output. They are required for the tool to run.<br><br>
`pip3 install rust_strings tabulate`<br><br>
When using, ensure the malapid.py and malapi_content.json are in the same directory.
# Usage
```
usage: malapid.py [-h] [-s] [-v] [-i] [-o OUT_FILE] file

positional arguments:
  file                  Input PE file to get strings data or text file with strings data already in it

optional arguments:
  -h, --help            show this help message and exit
  -s, --strings         Output all strings found
  -v, --verbose         Increase verbosity
  -i, --interesting-strings
                        Find URLs, IPs, and paths in strings
  -o OUT_FILE, --out-file OUT_FILE
                        Save the output to a file
