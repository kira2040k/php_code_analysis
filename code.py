#import libraries
import sys
import code_analysis as CA
import colors
#read file
def read_all_file():
    file = open(sys.argv[1],'r',encoding="utf8")
    file = file.read()
    return file 
#information about php code 
CA.info.GET_parameters(read_all_file())
CA.info.POST_parameters(read_all_file())
#scan SQL injection 


file = open(sys.argv[1],'r',encoding="utf8")
line_number = 0
print(colors.color.blue('vulnerability found:\n'))
CA.search.SQLi(read_all_file())
for line in file:
    CA.search.command_injection(line.strip('\n'),line_number)
    CA.search.LFI(line.strip('\n'),line_number)
    CA.search.XSS(line.strip('\n'),line_number)
    CA.search.SSRF(line.strip('\n'),line_number)
    CA.search.open_redirect(line.strip('\n'),line_number)
    CA.search.ID(line.strip('\n'),line_number)
    
    line_number = line_number + 1
