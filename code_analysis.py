import re,colors
class search():
    def command_injection(line,line_number):
        regex = "system\(.*\)|passthru\(.*\)|escapeshellcmd\(.*\)|pcntl_exec\(.*\)|exec\(.*\)|eval\(.*\)|assert\(.*\)"
        black_list = re.findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found execute functions on line: {line_number+1}'))   
            colors.color.reset()
    def LFI(line,line_number):
        regex = "include \$_.*|include_once \$_.*|require \$_.*|require_once \$_.*|readfile \$_.*"
        black_list = re.findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found LFI on line {line_number+1}'))   
            colors.color.reset()
    def XSS(line,line_number):
        regex = "echo \$.*|echo \$_[A-Z]{2,6}\[.*\]|echo \$\_SERVER\[\'PHP_SELF\'\]"
        black_list = re.findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found XSS on line {line_number+1}'))   
            colors.color.reset()
    def SSRF(line,line_number):

        regex = "file_get_contents\(\$.*\)|fopen\(\$.*\)|fread\(\$.*\)|fsockopen\(\$.*\)|curl_exec\(\$.*\)"
        black_list = re.findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found SSRF on line {line_number+1}'))   
            colors.color.reset()
    def open_redirect(line,line_number):

        regex = "header\(\$.*\)"
        black_list = re.findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found open redirect on line {line_number+1}'))   
            colors.color.reset()
    def ID(line,line_number):

        regex = "unserialize\(\.*\) |__wakeup\(\.*\)|__destruct\(\.*\)|__toString\(\.*\)"
        black_list = re.findall(regex, line)
        if(black_list):
            print(colors.color.red(f'found Insecure Deserialization on line {line_number+1}'))   
            colors.color.reset()
    def SQLi(file):
        regex = "query\(.*\)|mysql_query\(.*\)|get_results\(.*\)|get_var\(.*\)"
        black_list = re.findall(regex, file)
        if(black_list):
            for vuln in black_list:
                print(colors.color.red(f'found SQLi :{vuln}'))   
                colors.color.reset()
            


class info():
    def GET_parameters(file):
        regex = "\$_GET\[.*\]"
        black_list = re.findall(regex, file)
        if(black_list):
            for vuln in black_list:
                print(colors.color.green(f'GET parameter :{vuln[7:-2]}'))   
                colors.color.reset()
    def POST_parameters(file):
        regex = "\$_POST\[.*\]"
        black_list = re.findall(regex, file)
        if(black_list):
            for vuln in black_list:
                print(colors.color.green(f'POST parameter :{vuln[8:-2]}'))   
                colors.color.reset()
            

