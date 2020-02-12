#-*- coding: utf-8 -*-
'''Usage:
	python getsddl.py <file | folder>'''

import sys	
import win32security	as w32s

# ---------------------------------- Some global constants

OWNER_SEC_INF 	= 0x00000001
GROUP_SEC_INF 	= 0x00000002
DACL_SEC_INF  	= 0x00000004
SACL_SEC_INF  	= 0x00000008
LABEL_SEC_INF 	= 0x00000010
SDDL_REVISION_1 = 1

# ---------------------------------- 

def Usage():
	print(__doc__)
	sys.exit(0)
	
if len(sys.argv) < 2:	
	Usage()
else:
	PATH = sys.argv[1]
	
sd = w32s.GetFileSecurity (PATH, w32s.DACL_SECURITY_INFORMATION)

security_information = OWNER_SEC_INF | GROUP_SEC_INF | DACL_SEC_INF | SACL_SEC_INF
ststr = w32s.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, SDDL_REVISION_1, security_information)  
print(ststr)
