from os import listdir
import code_analysis as CA
from sys import argv
import os
def scan_files_in_folder(path):
    
    
    folders = listdir(path)
    
    for i2 in folders:
        try:
            if('.php' in i2):        

                file = open(f"{path}/{i2}","r",encoding="utf8",errors='ignore')
                file = file.read()
                line_number = 0
                print(f"{path}/{i2}")
                CA.info.GET_parameters(file)
                CA.info.POST_parameters(file)
                CA.check.check_all(f"{path}/{i2}")
                CA.search.SQLi(file)
                CA.search.check_file_upload(file)
        except:
            pass
    for i in folders:
        try:
            if ("." not in i and os.path.isdir(f"{path}/{i}")):
                scan_files_in_folder(f"{path}/{i}")
        except:
            pass
    return folders
    
if(len(argv) == 2):
    try:
        if(".php" in argv[1]):
            file = open(f"{argv[1]}","r",encoding="utf8",errors='ignore')
            file = file.read()
            line_number = 0
            CA.info.GET_parameters(file)
            CA.info.POST_parameters(file)
            CA.check.check_all(f"{argv[1]}")
            CA.search.SQLi(file)
            CA.search.check_file_upload(file)
            CA.info.finish()
        else:
            scan_files_in_folder(argv[1])
            CA.info.finish()
    except:
        pass
else:
    try:
        folders = scan_files_in_folder('.')
        CA.info.finish()
    except:
        pass
