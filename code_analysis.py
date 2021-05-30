import colors
from re import findall
from time import time
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


def count_vuln(vuln):
    if vuln == 0:
        return "0"
    else: 
        return vuln

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
        regex = "include \$_.*|include_once \$_.*|require \$_.*|require_once \$_.*|readfile \$_.*"
        black_list = findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found LFI on line {line_number+1}'))   
            colors.color.reset()
            number_vuln+=1
            LFI_number_vuln+=1
    def XSS(line,line_number):
        global number_vuln,XSS_number_vuln
        regex = "echo \$.*|echo \$_[A-Z]{2,6}\[.*\]|echo \$\_SERVER\[\'PHP\_SELF\'\]|echo \$\_SERVER\[\'SCRIPT\_NAME\'\]|echo \$\_SERVER\[\'HTTP\_USER\_AGENT\'\]|echo \$\_SERVER\[\'HTTP\_REFERER\'\]"
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
        regex = "query\(.*\)|mysql_query\(.*\)|get_results\(.*\)|get_var\(.*\)"
        black_list = findall(regex, file)
        regex2 = "\'\$.*\'|\"\$.*\""
        if(black_list):
            for vuln in black_list:
                black_list2 = findall(regex2,vuln)
                
                if(black_list2):
                    for vuln2 in black_list2:
                        print(colors.color.yellow(f"found SQLi: {vuln}"))
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
                if(vuln not in parameters):
                    print(colors.color.green(f'GET parameter :{vuln[7:-2]}'))
                    parameters.append(vuln)   
                    colors.color.reset()
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
        print(colors.color.blue(f"total number of vulnerabilities: {count_vuln(number_vuln)}"))
        print(colors.color.blue(check.number_of_vuln("SQLi",count_vuln(SQli_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("XSS",count_vuln(XSS_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("execute functions",count_vuln(command_injection_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("LFI",count_vuln(LFI_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("SSRF",count_vuln(SSRF_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("uplaod issues",count_vuln(check_file_upload_number_vuln))))
        print(colors.color.blue(check.number_of_vuln("host_header_injection",count_vuln(host_header_injection_number_vuln))))
        
        print(colors.color.blue(check.number_of_vuln("insecure deserialization",count_vuln(ID_number_vuln))))
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
