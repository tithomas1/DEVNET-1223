#!/usr/bin/python

#
# 27 Nov 2016
# check.py
#       Single ping for VIRL images in /etc/hosts 
#       Version 1.7
# 	V 1.8: 1Sept17: added 'sudo' to os.system command for alpine container
#

# import os for ping command
import os
import sys

FILE="/etc/hosts"
hosts=""
prefix=sys.argv[1]

try: 

  with open(FILE) as f:
    for i in f.readlines(): 
      hosts=i.strip()
      if not (i.strip().startswith(prefix)): 
        continue
      hip=i.split()[0]
      hn=i.split()[1]
      if os.system("sudo ping -c 1 -w 1 " + hip + "> /dev/null 2>&1") == 0:
        print hip, " is awake (", hn, ")"
      else: 
        print hip, " needs a nudge (",hn,")"

  f.close()


except:
  print "ERROR in looping through hosts (for loop)\n"
  exit(1)

#if __name__ == "__main__":
#    main()

# END OF SCRIPT
