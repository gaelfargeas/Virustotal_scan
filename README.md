# Virustotal_scan <img src="/img/vt_logo.ico" width="25" height="25" >

[![PyPI](https://img.shields.io/pypi/l/simplelogging.svg)](https://github.com/gaelfargeas/Virustotal_scan/blob/master/LICENSE)

Python interface for virustotal scan



## Prerequis :

Python +> 3.7

Install virustotal-python :

Windows :

    python -m pip install virustotal-python

Linux :

    pip3 install virustotal-python

## How to use :

Windows :

    python main.py

Linux :

    python3 main.py

### APP :

![VT scan app](/img/VT_scan.png)

### BUTTONS :
Select files : Select files and add them to File(s) List.
Select Directory : Select direcory and add all files in it to File(s) List.
Delete : remove the selected item in File(s) List
Start scan : start scanning all files in File(s) List.
Stop scan : stop scanning all files in File(s) List.

### WARNING :

Avoid to select an link file with Select files or Select Directory.

File can be add multiple time to file(s) list.

Stop scan can take time, it wait until the current file scan finish.

Exit can take time, it wait until the current file scan finish then properly stop thread.

### INFORMATIONS :

FILE MUST NOT EXCEED 32MB.

### BUGS


## Library used :

virustotal-python (https://github.com/Dextroz/virustotal-python , license MIT)

