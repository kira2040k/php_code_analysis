from os import listdir
import code_analysis as CA
from sys import argv
import os
def scan_files_in_folder(path):
    
    if(os.path.isdir(path)):
       folders = listdir(path)
       for i2 in folders:
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
               
       for i in folders:
           if ("." not in i):
               scan_files_in_folder(f"{path}/{i}")
       return folders
    
if(len(argv) == 2):
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
else:
    folders = scan_files_in_folder('.')
    CA.info.finish()
