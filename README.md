# Request minimizer
This is a helper tool to perform HTTP request minimization, i.e. delete parameters that are not relevant. Examples include: random ad cookies, cachebusting nonces etc.

# Installation

1.	Download Burp Suite : http://portswigger.net/burp/download.html
2.	Download Jython standalone JAR: http://www.jython.org/downloads.html
3.	Open burp -> Extender -> Options -> Python Environment -> Select File -> Choose the Jython standalone JAR
4.  Install packages from requirements.txt  using pip install -r requirements (use jython's pip!)
4.  Specify "Folder for loading modules" in Extender->Options->Python environment. It should reflect your global or virtualenv site-packages. E.g. "C:\jython2.7\lib\site-packages" for WIN, or /opt/jython/Lib/site-packages fo Archlinux. If you use virtualenv (you should!) - it would be /path/to/virtualenv/Lib/site-packages.
4.	Download the extension .py file.
5.	Open Burp -> Extender -> Extensions -> Add -> Choose the file.

# Usage

After installation, a new option will be added to repeater's context menu, named "Minimize and send to repeater". Click that, wait and a new tab with minimized request will appear.

# Demo

![Demo](https://raw.githubusercontent.com/ngo/burp-request-minimizer/master/sample.gif)
