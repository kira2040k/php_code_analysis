#import libraries
import sys
import code_analysis as CA

#read file
try:
    file = open(sys.argv[1],'r',encoding="utf8")
    line_number = 0

    for line in file:
        CA.search.command_injection(line.strip('\n'),line_number)
        CA.search.LFI(line.strip('\n'),line_number)
        CA.search.XSS(line.strip('\n'),line_number)
        CA.search.SSRF(line.strip('\n'),line_number)
        CA.search.open_redirect(line.strip('\n'),line_number)
        line_number = line_number + 1
except:
    print(f'[+] usage: python {sys.argv[0]} file.php [+]')
