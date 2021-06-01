from os import listdir
import code_analysis as CA
from sys import argv
import os
import colors
import argparse
parse = argparse.ArgumentParser()
parse.add_argument('-p',"--path", action='store', type=str)
parse.add_argument('-s',
                       '--server',
                       action='store_true',
                       help='enable the long listing format')
args = parse.parse_args()
server = args.server


print(f"""{colors.color.purple('')}


           __                             __                           __           _     
    ____  / /_  ____      _________  ____/ /__      ____ _____  ____ _/ /_  _______(_)____
   / __ \/ __ \/ __ \    / ___/ __ \/ __  / _ \    / __ `/ __ \/ __ `/ / / / / ___/ / ___/
  / /_/ / / / / /_/ /   / /__/ /_/ / /_/ /  __/   / /_/ / / / / /_/ / / /_/ (__  ) (__  ) 
 / .___/_/ /_/ .___/____\___/\____/\__,_/\___/____\__,_/_/ /_/\__,_/_/\__, /____/_/____/  
/_/         /_/   /_____/                   /_____/                  /____/               




"""
)





print(f"""
{colors.color.purple('[+]------------------------------------------[+]')}

            twitter:kira_321k
            insta:at9w

[+]------------------------------------------[+]

""")
colors.color.reset()
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
            if (os.path.isdir(f"{path}/{i}")):
                scan_files_in_folder(f"{path}/{i}")
        except:
            pass
    
    
if(args.path):
    path = args.path
    server = args.server
    
    if(".php" in args.path):
        file = open(f"{args.path}","r",encoding="utf8",errors='ignore')
        file = file.read()
        line_number = 0
        CA.info.GET_parameters(file)
        CA.info.POST_parameters(file)
        CA.check.check_all(f"{args.path}")
        CA.search.SQLi(file)
        CA.search.check_file_upload(file)
        CA.info.finish()
        CA.info.fix()
        
        if(server):
            
            CA.server.php(path)
    else:
        scan_files_in_folder(args.path)
        CA.info.finish()
        CA.info.fix()
        if(server):
            
            CA.server.php(path)

else:
    
    try:
        
        folders = scan_files_in_folder('.')
        CA.info.finish()
        CA.info.fix()
        if(server):
            
            CA.server.php('.')
    except:
        pass
