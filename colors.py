class color:
    def reset():
        print(u"\u001b[0m",end="")
    def red(text):
        color= (f"\033[1;31;40m{text}")
        
        return color
    def blue(text):
        color = (f"\033[1;34;40m{text}")
        
        return color    
    def yellow(text):
        color  = (f"\033[1;33;40m{text}")
        
        return color
    def gray(text):
        color = (f"\033[1;30;40m{text}")
        return colorr
    def purple(text):
        color = (f"\u001b[35m{text}")
        return color
    def cyan(text):
        color = (f"\033[1;36;40m{text}")
        return color
    def green(text):
        color = (f"\033[1;32;40m{text}")
        return color
    def white(text):
        color = (f"\033[1;37;40m{text}")
        return color
    def black(text):
        color = (f"\u001b[30;1m{text}")
        return color