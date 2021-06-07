import colors
from re import findall
from time import time
<<<<<<< HEAD
import subprocess
import threading
from os import listdir
import os
import requests
import sys

=======
>>>>>>> cc80b37a0d67c7900f568a0ab22873add17700bd
start_time = time()
number_vuln = 0
XSS_number_vuln = 0
SQli_number_vuln = 0
LFI_number_vuln = 0
command_injection_number_vuln = 0
SSRF_number_vuln = 0
open_redirect_number_vuln = 0
host_header_injection_number_vuln = 0
check_file_upload_number_vuln = 0
ID_number_vuln = 0





class search():
    def command_injection(line,line_number):
        global number_vuln,command_injection_number_vuln
        regex = "system\(.*\)|passthru\(.*\)|escapeshellcmd\(.*\)|pcntl_exec\(.*\)|exec\(.*\)|eval\(.*\)|assert\(.*\)"
        black_list = findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found execute functions on line: {line_number+1}'))   
            colors.color.reset()
            number_vuln+=1
            command_injection_number_vuln+=1
    def LFI(line,line_number):
        global number_vuln,LFI_number_vuln 
        regex = "include \$_.*|include_once \$_.*|require \$_.*|require_once \$_.*|readfile \$_.*|include\(.*\$.*\)"
        black_list = findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found LFI on line {line_number+1}'))   
            colors.color.reset()
            number_vuln+=1
            LFI_number_vuln+=1
    def XSS(line,line_number):
        global number_vuln,XSS_number_vuln
        regex = "echo \$.*|echo \$_[A-Z]{2,6}\[.*\]|echo \$\_SERVER\[\'PHP\_SELF\'\]|echo \$\_SERVER\[\'SCRIPT\_NAME\'\]|echo \$\_SERVER\[\'HTTP\_USER\_AGENT\'\]|echo \$\_SERVER\[\'HTTP\_REFERER\'\]|echo(.*\$_[A-Z]{2,6}\[.*\])|echo .*\$"
        black_list = findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found XSS on line {line_number+1}'))   
            colors.color.reset()
            number_vuln+=1
            XSS_number_vuln+=1
    def SSRF(line,line_number):
        global number_vuln,SSRF_number_vuln
        regex = "file_get_contents\(\$.*\)|fopen\(\$.*\)|fread\(\$.*\)|fsockopen\(\$.*\)|curl_exec\(\$.*\)"
        black_list = findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found SSRF on line {line_number+1}'))   
            colors.color.reset()
            number_vuln+=1
            SSRF_number_vuln+=1
    def open_redirect(line,line_number):
        global number_vuln,open_redirect_number_vuln
        regex = "header\(\$.*\)"
        black_list = findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found open redirect on line {line_number+1}'))   
            colors.color.reset()
            number_vuln+=1
            open_redirect_number_vuln+=1
    def ID(line,line_number):
        global number_vuln,ID_number_vuln
        regex = "unserialize\(\.*\) |__wakeup\(\.*\)|__destruct\(\.*\)|__toString\(\.*\)"
        black_list = findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found Insecure Deserialization on line {line_number+1}'))   
            colors.color.reset()
            number_vuln+=1
            ID_number_vuln+=1
    def SQLi(file):
        global number_vuln,SQli_number_vuln
        regex = "query\(.*\)|mysql_query\(.*\)|get_results\(.*\)|get_var\(.*\)|mysqli_query\(.*\)"
        black_list = findall(regex, file)
        regex2 = "\'\$.*\'|\"\$.*\""
        if(black_list):
            for vuln in black_list:
                black_list2 = findall(regex2,vuln)
                
                if(black_list2):
                    for vuln2 in black_list2:
                        print(colors.color.yellow(f"found SQLi: {vuln}")) #find SQli but not sure 
                        number_vuln+=1
                        SQli_number_vuln+=1
                        
                else:
                    print(colors.color.red(f'found SQLi :{vuln}'))   
                    colors.color.reset()
                    number_vuln+=1 
                    SQli_number_vuln+=1   
    def host_header_injection(line,line_number):
        global number_vuln,host_header_injection_number_vuln
        regex = "\$\_SERVER\[\'HOST\'\]"
        black_list = findall(regex, line)
        if(black_list):
            print(colors.color.red(f'Host header injection on line {line_number+1}'))   
            colors.color.reset()
            number_vuln+=1
            host_header_injection_number_vuln+=1
    def check_file_upload(file):
        global number_vuln,check_file_upload_number_vuln
        if('$_FILES' in file):
            regex = "\$\_FILES\[.*\]\[\"size\"\]|\[.mime.\]|PATHINFO\_EXTENSION"
            black_list = findall(regex, file)
            if(len(black_list) == 0 ):
                print(colors.color.red(f'file upload (mime type or size or extension)'))   
                colors.color.reset()
                number_vuln+=1
                check_file_upload_number_vuln+=1

class info():
    def GET_parameters(file):
        regex = "\$_GET\[.*\]"
        black_list = findall(regex, file)
        parameters = []
        if(black_list):
            for vuln in black_list:
<<<<<<< HEAD

                    param = vuln[7:-2]
                    param = sub(r'\'.*|\$|\".*|\].*|\[.*|&&.*|=>|,.*|\|\|.*', '', param) 
                    
                    if(param not in parameters and len(param) != 0 ):    
                        parameters.append(param)
                        print(colors.color.cyan(f'GET parameter :{param}'))

                        colors.color.reset()
=======
                if(vuln not in parameters):
                    print(colors.color.green(f'GET parameter :{vuln[7:-2]}'))
                    parameters.append(vuln)   
                    colors.color.reset()
>>>>>>> cc80b37a0d67c7900f568a0ab22873add17700bd
    def POST_parameters(file):
        regex = "\$_POST\[.*\]"
        black_list = findall(regex, file)
        parameters = []
        if(black_list):
            for vuln in black_list:
                if(vuln not in parameters):
                    print(colors.color.green(f'POST parameter :{vuln[8:-2]}'))  
                    parameters.append(vuln) 
                    colors.color.reset()
    def finish():
        global  number_vuln , start_time , SQli_number_vuln , XSS_number_vuln , command_injection_number_vuln, LFI_number_vuln, SSRF_number_vuln, check_file_upload_number_vuln , host_header_injection_number_vuln , open_redirect_number_vuln , ID_number_vuln
        print(colors.color.blue("-"*50))
        print(colors.color.blue(f"total number of vulnerabilities: {number_vuln}"))
        print(colors.color.blue(check.number_of_vuln("XSS",check.count_vuln(XSS_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("execute functions",check.count_vuln(command_injection_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("LFI",check.count_vuln(LFI_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("SSRF",check.count_vuln(SSRF_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("uplaod issues",check.count_vuln(check_file_upload_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("host_header_injection",check.count_vuln(host_header_injection_number_vuln))))
        
        print(colors.color.blue(check.number_of_vuln("insecure deserialization",check.count_vuln(ID_number_vuln))))
        print(colors.color.blue(f"execute time: {time() - start_time}/s"))
        colors.color.reset()
class check():
    def check_all(file):
        file = open(file,"r",encoding='utf-8',errors='ignore')
        line_number = 0
        for line in file:            
            search.command_injection(line.strip('\n'),line_number)
            search.LFI(line.strip('\n'),line_number)
            search.XSS(line.strip('\n'),line_number)
            search.SSRF(line.strip('\n'),line_number)
            search.open_redirect(line.strip('\n'),line_number)
            search.ID(line.strip('\n'),line_number)
            search.host_header_injection(line.strip('\n'),line_number)
            line_number = line_number + 1
    def number_of_vuln(name,number):
        if(number != 0):
            return f"{name} vulnerability :{number}"
        else:
            False
    def count_vuln(vuln):
        if vuln == 0:
            return "0"
        else: 
            return vuln
<<<<<<< HEAD


class server():
    global found_XSS_open_server
    def scan_files_in_folder(path,original_path):
        folders = listdir(path)
        
        for i2 in folders:
        
            if('.php' in i2):
                path2 = sub(r'[A-Z|a-z]:[\\|\/]', ' ', path).replace(" ","").replace("  ","")
                                     
                file = open(f"{path}/{i2}","r",encoding="utf8",errors='ignore')
                file = file.read()
                
                payloads = ['x"><img src=adsad onerror=alert(123)//>//','<svg/onload=alert(1)',"<ScRiPt>alert(1)</sCriPt>"]
                
                GET_parameters = server.GET_parameters(file)
                
                for par in GET_parameters:
                    par = par.replace('\'','').replace("\"","").replace("[","").replace("]","") 
                    for payload in payloads:
                        attack_url = path.replace(original_path,"")  
                        url = f"http://localhost:2003/{attack_url}/{i2.replace('./','')}?{par}={payload}"
                        
                              
                        r = requests.get(url)
                        if payload in r.text and url not in found_XSS_open_server:
                            print(colors.color.orange(f"XSS found {url}"))
                            colors.color.reset()
                            found_XSS_open_server.append(url)
        for i in folders:
            try:
                if (os.path.isdir(f"{path}/{i}")):
                    server.scan_files_in_folder(f"{path}/{i}",original_path)
            except:
                pass

        
    def GET_parameters(file):
        
        regex = "\$_GET\[.*\]"
        black_list = findall(regex, file)
        parameters = []
        if(black_list):
            for vuln in black_list:
                
                    param = vuln[7:-2]
                    param = sub(r'\'.*|\$|\".*|\].*|\[.*|&&.*|=>|,.*|\|\|.*', '', param)
                    if(param not in parameters):    
                        parameters.append(param)
                        

        return parameters
        


    def open_server(path):  
        
        try:
            subprocess.run(['php','-S','localhost:2003','-t',path],capture_output=True) 
        except:
            print("""
            install php 
            or 
            add php on your system env
            """)
            os._exit(1)
    
    def php(path):
        print(colors.color.orange("-"*50))
        print("start php server and scan ")
        try:
            t1 = threading.Thread(target=server.open_server, args=(path,))
            t1.start()
            
        except:
            pass
        
        if(".php" in path):
            
            GET_parameters = server.GET_parameters(path)
            payloads = ['x"><img src=adsad onerror=alert(123)//>//','<svg/onload=alert(1)',"<ScRiPt>alert(1)</sCriPt>"]

            for par in GET_parameters:
                par = par.replace('\'','').replace("\"","").replace("[","").replace("]","") 
                
                for payload in payloads:
                    url = f"http://localhost:2003/{path}?{par}={payload}"
                    
                    r = requests.get(url)
                    if payload in r.text:
                        print(colors.color.orange(f"XSS found {url}"))
                        colors.color.reset()
        else:
            server.scan_files_in_folder(path,path)
        print("")
        print("-"*50)
        colors.color.reset()
        print("scan finish")
        
        os._exit(1)

=======
>>>>>>> cc80b37a0d67c7900f568a0ab22873add17700bd
