#-*- coding: utf-8 -*-
'''Usage:
  1) Read and parse file ACLs in SDDL format:
    python readssdl.py [path]<filename>
  2) Parse SDDL string:
    python readssdl.py /S:<SDDL>

SDDL is a security descriptor definition, like this:
  D:PAI(A;;0x1301bf;;;AU)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;BU)
  Security Descriptor String Format:
    O:owner_sid
    G:group_sid
    D:dacl_flags(string_ace1)(string_ace2)... (string_acen)
    S:sacl_flags(string_ace1)(string_ace2)... (string_acen)
  Where:
    dacl_flags:
      Security descriptor control flags that apply to the DACL. 
      For a description of these control flags, see the 'SetSecurityDescriptorControl' function.
      The dacl_flags string can be a concatenation of zero or more of the following strings:
      "P"                 SDDL_PROTECTED        The SE_DACL_PROTECTED flag is set.
      "AR"                SDDL_AUTO_INHERIT_REQ The SE_DACL_AUTO_INHERIT_REQ flag is set.
      "AI"                SDDL_AUTO_INHERITED   The SE_DACL_AUTO_INHERITED flag is set.
      "NO_ACCESS_CONTROL" SSDL_NULL_ACL         The ACL is null.
    string_ace:
      ace_type ;ace_flags;rights;object_guid;inherit_object_guid;account_sid;
    Constants (from Sddl.h):
      ace_type:
        "A"   SDDL_ACCESS_ALLOWED                  ACCESS_ALLOWED_ACE_TYPE            0x00
        "D"   SDDL_ACCESS_DENIED                   ACCESS_DENIED_ACE_TYPE             0x01
        "OA"  SDDL_OBJECT_ACCESS_ALLOWED           ACCESS_ALLOWED_OBJECT_ACE_TYPE     0x05
        "OD"  SDDL_OBJECT_ACCESS_DENIED            ACCESS_DENIED_OBJECT_ACE_TYPE      0x06
        "AU"  SDDL_AUDIT                           SYSTEM_AUDIT_ACE_TYPE              0x02
        "AL"  SDDL_ALARM                           SYSTEM_ALARM_ACE_TYPE              0x03
        "OU"  SDDL_OBJECT_AUDIT	                   SYSTEM_AUDIT_OBJECT_ACE_TYPE       0x07
        "OL"  SDDL_OBJECT_ALARM	                   SYSTEM_ALARM_OBJECT_ACE_TYPE       0x08
        "ML"  SDDL_MANDATORY_LABEL                 SYSTEM_MANDATORY_LABEL_ACE_TYPE    0x11
        "XA"  SDDL_CALLBACK_ACCESS_ALLOWED         ACCESS_ALLOWED_CALLBACK_ACE_TYPE   0x09
        "XD"  SDDL_CALLBACK_ACCESS_DENIED          ACCESS_DENIED_CALLBACK_ACE_TYPE    0x0A
        "RA"  SDDL_RESOURCE_ATTRIBUTE              SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE 0x12
        "SP"  SDDL_SCOPED_POLICY_ID                SYSTEM_SCOPED_POLICY_ID_ACE_TYPE   0x13
        "XU"  SDDL_CALLBACK_AUDIT                  SYSTEM_AUDIT_CALLBACK_ACE_TYPE     0x0D
        "ZA"  SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED  ACCESS_ALLOWED_CALLBACK_ACE_TYPE   0x09
      ace_flags:
        "CI"  SDDL_CONTAINER_INHERIT               CONTAINER_INHERIT_ACE              0x02
        "OI"  SDDL_OBJECT_INHERIT                  OBJECT_INHERIT_ACE                 0x01
        "NP"  SDDL_NO_PROPAGATE                    NO_PROPAGATE_INHERIT_ACE           0x04
        "IO"  SDDL_INHERIT_ONLY                    INHERIT_ONLY_ACE                   0x08
        "ID"  SDDL_INHERITED                       INHERITED_ACE                      0x10
        "SA"  SDDL_AUDIT_SUCCESS                   SUCCESSFUL_ACCESS_ACE_FLAG         0x40
        "FA"  SDDL_AUDIT_FAILURE                   FAILED_ACCESS_ACE_FLAG             0x80
      rights:
        --- Generic access rights:
        "GA"  SDDL_GENERIC_ALL         GENERIC_ALL
        "GR"  SDDL_GENERIC_READ        GENERIC_READ
        "GW"  SDDL_GENERIC_WRITE       GENERIC_WRITE
        "GX"  SDDL_GENERIC_EXECUTE     GENERIC_EXECUTE
        --- Standard access rights:
        "RC"  SDDL_READ_CONTROL        READ_CONTROL
        "SD"  SDDL_STANDARD_DELETE     DELETE
        "WD"  SDDL_WRITE_DAC           WRITE_DAC
        "WO"  SDDL_WRITE_OWNER         WRITE_OWNER
        --- Directory service object access rights:
        "RP"  SDDL_READ_PROPERTY       ADS_RIGHT_DS_READ_PROP
        "WP"  SDDL_WRITE_PROPERTY      ADS_RIGHT_DS_WRITE_PROP
        "CC"  SDDL_CREATE_CHILD        ADS_RIGHT_DS_CREATE_CHILD
        "DC"  SDDL_DELETE_CHILD        ADS_RIGHT_DS_DELETE_CHILD
        "LC"  SDDL_LIST_CHILDREN       ADS_RIGHT_ACTRL_DS_LIST
        "SW"  SDDL_SELF_WRITE          ADS_RIGHT_DS_SELF
        "LO"  SDDL_LIST_OBJECT 	       ADS_RIGHT_DS_LIST_OBJECT
        "DT"  SDDL_DELETE_TREE 	       ADS_RIGHT_DS_DELETE_TREE
        "CR"  SDDL_CONTROL_ACCESS      ADS_RIGHT_DS_CONTROL_ACCESS
        --- File access rights:
        "FA"  SDDL_FILE_ALL            FILE_ALL_ACCESS
        "FR"  SDDL_FILE_READ           FILE_GENERIC_READ
        "FW"  SDDL_FILE_WRITE          FILE_GENERIC_WRITE
        "FX"  SDDL_FILE_EXECUTE        FILE_GENERIC_EXECUTE
        --- Registry key access rights:
        "KA"  SDDL_KEY_ALL             KEY_ALL_ACCESS
        "KR"  SDDL_KEY_READ            KEY_READ
        "KW"  SDDL_KEY_WRITE           KEY_WRITE
        "KX"  SDDL_KEY_EXECUTE         KEY_EXECUTE
        --- Mandatory label rights:
        "NR"  SDDL_NO_READ_UP          SYSTEM_MANDATORY_LABEL_NO_READ_UP
        "NW"  SDDL_NO_WRITE_UP         SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
        "NX"  SDDL_NO_EXECUTE_UP       SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
      object_guid:
        A string representation of a GUID that indicates the value of the ObjectType member of an object-specific 
        ACE structure, such as ACCESS_ALLOWED_OBJECT_ACE. The GUID string uses the format returned by the 
        UuidToString function.
      inherit_object_guid:
        A string representation of a GUID that indicates the value of the InheritedObjectType member of an 
        object-specific ACE structure. The GUID string uses the UuidToString format.
      account_sid:
       "AN"	SDDL_ANONYMOUS                     Anonymous logon. The corresponding RID is SECURITY_ANONYMOUS_LOGON_RID.
       "AO"	SDDL_ACCOUNT_OPERATORS             Account operators. The corresponding RID is DOMAIN_ALIAS_RID_ACCOUNT_OPS.
       "AU"	SDDL_AUTHENTICATED_USERS           Authenticated users. The corresponding RID is SECURITY_AUTHENTICATED_USER_RID.
       "BA"	SDDL_BUILTIN_ADMINISTRATORS        Built-in administrators. The corresponding RID is DOMAIN_ALIAS_RID_ADMINS.
       "BG"	SDDL_BUILTIN_GUESTS                Built-in guests. The corresponding RID is DOMAIN_ALIAS_RID_GUESTS.
       "BO"	SDDL_BACKUP_OPERATORS              Backup operators. The corresponding RID is DOMAIN_ALIAS_RID_BACKUP_OPS.
       "BU"	SDDL_BUILTIN_USERS                 Built-in users. The corresponding RID is DOMAIN_ALIAS_RID_USERS.
       "CA"	SDDL_CERT_SERV_ADMINISTRATORS      Certificate publishers. The corresponding RID is DOMAIN_GROUP_RID_CERT_ADMINS.
       "CD"	SDDL_CERTSVC_DCOM_ACCESS           Users who can connect to certification authorities using Distributed Component Object Model (DCOM). The corresponding RID is DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP.
       "CG"	SDDL_CREATOR_GROUP                 Creator group. The corresponding RID is SECURITY_CREATOR_GROUP_RID.
       "CO"	SDDL_CREATOR_OWNER                 Creator owner. The corresponding RID is SECURITY_CREATOR_OWNER_RID.
       "DA"	SDDL_DOMAIN_ADMINISTRATORS         Domain administrators. The corresponding RID is DOMAIN_GROUP_RID_ADMINS.
       "DC"	SDDL_DOMAIN_COMPUTERS              Domain computers. The corresponding RID is DOMAIN_GROUP_RID_COMPUTERS.
       "DD"	SDDL_DOMAIN_DOMAIN_CONTROLLERS     Domain controllers. The corresponding RID is DOMAIN_GROUP_RID_CONTROLLERS.
       "DG"	SDDL_DOMAIN_GUESTS                 Domain guests. The corresponding RID is DOMAIN_GROUP_RID_GUESTS.
       "DU"	SDDL_DOMAIN_USERS                  Domain users. The corresponding RID is DOMAIN_GROUP_RID_USERS.
       "EA"	SDDL_ENTERPRISE_ADMINS             Enterprise administrators. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_ADMINS.
       "ED"	SDDL_ENTERPRISE_DOMAIN_CONTROLLERS Enterprise domain controllers. The corresponding RID is SECURITY_SERVER_LOGON_RID.
       "HI"	SDDL_ML_HIGH                       High integrity level. The corresponding RID is SECURITY_MANDATORY_HIGH_RID.
       "IU"	SDDL_INTERACTIVE                   Interactively logged-on user. This is a group identifier added to the token of a process when it was logged on interactively. The corresponding logon type is LOGON32_LOGON_INTERACTIVE. The corresponding RID is SECURITY_INTERACTIVE_RID.
       "LA"	SDDL_LOCAL_ADMIN                   Local administrator. The corresponding RID is DOMAIN_USER_RID_ADMIN.
       "LG"	SDDL_LOCAL_GUEST                   Local guest. The corresponding RID is DOMAIN_USER_RID_GUEST.
       "LS"	SDDL_LOCAL_SERVICE                 Local service account. The corresponding RID is SECURITY_LOCAL_SERVICE_RID.
       "LW"	SDDL_ML_LOW                        Low integrity level. The corresponding RID is SECURITY_MANDATORY_LOW_RID.
       "ME"	SDDL_MLMEDIUM                      Medium integrity level. The corresponding RID is SECURITY_MANDATORY_MEDIUM_RID.
       "MU"	SDDL_PERFMON_USERS                 Performance Monitor users.
       "NO"	SDDL_NETWORK_CONFIGURATION_OPS     Network configuration operators. The corresponding RID is DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS.
       "NS"	SDDL_NETWORK_SERVICE               Network service account. The corresponding RID is SECURITY_NETWORK_SERVICE_RID.
       "NU"	SDDL_NETWORK                       Network logon user. This is a group identifier added to the token of a process when it was logged on across a network. The corresponding logon type is LOGON32_LOGON_NETWORK. The corresponding RID is SECURITY_NETWORK_RID.
       "PA"	SDDL_GROUP_POLICY_ADMINS           Group Policy administrators. The corresponding RID is DOMAIN_GROUP_RID_POLICY_ADMINS.
       "PO"	SDDL_PRINTER_OPERATORS             Printer operators. The corresponding RID is DOMAIN_ALIAS_RID_PRINT_OPS.
       "PS"	SDDL_PERSONAL_SELF                 Principal self. The corresponding RID is SECURITY_PRINCIPAL_SELF_RID.
       "PU"	SDDL_POWER_USERS                   Power users. The corresponding RID is DOMAIN_ALIAS_RID_POWER_USERS.
       "RC"	SDDL_RESTRICTED_CODE               Restricted code. This is a restricted token created using the CreateRestrictedToken function. The corresponding RID is SECURITY_RESTRICTED_CODE_RID.
       "RD"	SDDL_REMOTE_DESKTOP                Terminal server users. The corresponding RID is DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS.
       "RE"	SDDL_REPLICATOR                    Replicator. The corresponding RID is DOMAIN_ALIAS_RID_REPLICATOR.
       "RO"	SDDL_ENTERPRISE_RO_DCs             Enterprise Read-only domain controllers. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.
       "RS"	SDDL_RAS_SERVERS                   RAS servers group. The corresponding RID is DOMAIN_ALIAS_RID_RAS_SERVERS.
       "RU"	SDDL_ALIAS_PREW2KCOMPACC           Alias to grant permissions to accounts that use applications compatible with operating systems previous to Windows 2000. The corresponding RID is DOMAIN_ALIAS_RID_PREW2KCOMPACCESS.
       "SA"	SDDL_SCHEMA_ADMINISTRATORS         Schema administrators. The corresponding RID is DOMAIN_GROUP_RID_SCHEMA_ADMINS.
       "SI"	SDDL_ML_SYSTEM                     System integrity level. The corresponding RID is SECURITY_MANDATORY_SYSTEM_RID.
       "SO"	SDDL_SERVER_OPERATORS              Server operators. The corresponding RID is DOMAIN_ALIAS_RID_SYSTEM_OPS.
       "SU"	SDDL_SERVICE                       Service logon user. This is a group identifier added to the token of a process when it was logged as a service. The corresponding logon type is LOGON32_LOGON_SERVICE. The corresponding RID is SECURITY_SERVICE_RID.
       "SY"	SDDL_LOCAL_SYSTEM                  Local system. The corresponding RID is SECURITY_LOCAL_SYSTEM_RID.
       "WD"	SDDL_EVERYONE                      Everyone. The corresponding RID is SECURITY_WORLD_RID.
    For Details: 
       ACE Strings: https://docs.microsoft.com/ru-ru/windows/win32/secauthz/ace-strings
       SID Strings: https://docs.microsoft.com/ru-ru/windows/win32/secauthz/sid-strings
       Security Descriptor Definition Language: https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language
       Security Descriptor Definition Language for Conditional ACEs: https://docs.microsoft.com/ru-ru/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-
       Access Mask Format: https://docs.microsoft.com/ru-ru/windows/win32/secauthz/access-mask-format
'''

# ================================================== Initialisation

import os, sys, re

# debug = 1
# debug = 2

def Usage():
	print(__doc__)
	sys.exit(0)

if len(sys.argv) < 2:
	if 'debug' in dict(globals()):
		if debug == 1:
			param = 'README.md'
		elif debug == 2:
			param = '/S:D:AI(A;ID;0x1301bf;;;AU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1301bf;;;BU)'
	else:
		Usage()
else:
	param = sys.argv[1]

m = re.search('^/[sS]:(.+?)$', param)
if m:
	sddl = m.group(1)
	case = 2
else:
	case = 1
	filename = param
	try:					# Check if file exists
		f = open(filename)
		f.close()
	except IOError:
		print("ERROR: Cannot open file: ", filename)
		print("Terminated!")	
		sys.exit(1)

# ================================================== SSDL and ACE Constants (see Sddl.h):

C_DELETE      				= 0x00010000
C_READ_CONTROL				= 0x00020000
C_WRITE_DAC   				= 0x00040000
C_WRITE_OWNER 				= 0x00080000
C_SYNCHRONIZE 				= 0x00100000
C_STANDARD_RIGHTS_REQUIRED  = 0x000F0000

C_STANDARD_RIGHTS_READ   	= C_READ_CONTROL
C_STANDARD_RIGHTS_WRITE  	= C_READ_CONTROL
C_STANDARD_RIGHTS_EXECUTE	= C_READ_CONTROL

C_FILE_READ_DATA           	= 0x0001
C_FILE_LIST_DIRECTORY      	= 0x0001
C_FILE_WRITE_DATA          	= 0x0002
C_FILE_ADD_FILE            	= 0x0002
C_FILE_APPEND_DATA         	= 0x0004
C_FILE_ADD_SUBDIRECTORY    	= 0x0004
C_FILE_CREATE_PIPE_INSTANCE	= 0x0004

C_FILE_READ_EA         		= 0x0008
C_FILE_WRITE_EA        		= 0x0010
C_FILE_EXECUTE         		= 0x0020
C_FILE_TRAVERSE        		= 0x0020
C_FILE_DELETE_CHILD    		= 0x0040
C_FILE_READ_ATTRIBUTES 		= 0x0080
C_FILE_WRITE_ATTRIBUTES		= 0x0100

C_FILE_ALL_ACCESS = (
	C_STANDARD_RIGHTS_REQUIRED | 
	C_SYNCHRONIZE 			   | 
	0x1FF
)

C_FILE_GENERIC_READ = (
	C_STANDARD_RIGHTS_READ     |
	C_FILE_READ_DATA           |
	C_FILE_READ_ATTRIBUTES     |
	C_FILE_READ_EA             |
	C_SYNCHRONIZE
)

C_FILE_GENERIC_WRITE = (
	C_STANDARD_RIGHTS_WRITE    |
	C_FILE_WRITE_DATA          |
	C_FILE_WRITE_ATTRIBUTES    |
	C_FILE_WRITE_EA            |
	C_FILE_APPEND_DATA         |
	C_SYNCHRONIZE
)

C_FILE_GENERIC_EXECUTE = (
	C_STANDARD_RIGHTS_EXECUTE  |
	C_FILE_READ_ATTRIBUTES     |
	C_FILE_EXECUTE             |
	C_SYNCHRONIZE
)

C_KEY_QUERY_VALUE 			= 0x0001
C_KEY_SET_VALUE 			= 0x0002
C_KEY_CREATE_SUB_KEY 		= 0x0004
C_KEY_ENUMERATE_SUB_KEYS 	= 0x0008
C_KEY_NOTIFY				= 0x0010
C_KEY_CREATE_LINK			= 0x0020

C_STANDARD_RIGHTS_REQUIRED 	= (
	C_DELETE			|
	C_READ_CONTROL		|
	C_WRITE_DAC			|
	C_WRITE_OWNER
)

C_KEY_ALL_ACCESS = (				# 0xF003F
	C_STANDARD_RIGHTS_REQUIRED |
	C_KEY_QUERY_VALUE		   |
	C_KEY_SET_VALUE			   |
	C_KEY_CREATE_SUB_KEY	   |
	C_KEY_ENUMERATE_SUB_KEYS   |
	C_KEY_NOTIFY			   |
	C_KEY_CREATE_LINK
)

C_KEY_WRITE = (						# 0x20006
	C_STANDARD_RIGHTS_WRITE	   |
	C_KEY_SET_VALUE			   |
	C_KEY_CREATE_SUB_KEY
)

# C_FILE_ALL_ACCESS      	 = 0x001F01FF
# C_FILE_GENERIC_WRITE   	 = 0x00120116
# C_FILE_GENERIC_READ    	 = 0x00120089
# C_FILE_GENERIC_EXECUTE 	 = 0x001200A0
# C_STANDARD_RIGHTS_REQUIRED = 0x000F0000
# C_KEY_ALL_ACCESS           = 0x000F003F
# C_KEY_WRITE           	 = 0x00020006

SDDL_TYPE = {
	"A" : ("ACCESS_ALLOWED",			"ACCESS_ALLOWED_ACE_TYPE",				0x00),			# Access allowed
	"D" : ("ACCESS_DENIED",			"ACCESS_DENIED_ACE_TYPE",				0x01),			# Access denied
	"OA": ("OBJECT_ACCESS_ALLOWED",	"ACCESS_ALLOWED_OBJECT_ACE_TYPE",		0x05),			# Object access allowed
	"OD": ("OBJECT_ACCESS_DENIED",		"ACCESS_DENIED_OBJECT_ACE_TYPE",		0x06),			# Object access denied
	"AU": ("AUDIT",						"SYSTEM_AUDIT_ACE_TYPE",				0x02),			# Audit
	"AL": ("ALARM",						"SYSTEM_ALARM_ACE_TYPE",				0x03),			# Alarm
	"OU": ("OBJECT_AUDIT",				"SYSTEM_AUDIT_OBJECT_ACE_TYPE",		0x07),			# Object audit
	"OL": ("OBJECT_ALARM",				"SYSTEM_ALARM_OBJECT_ACE_TYPE",		0x08),			# Object alarm
	"ML": ("MANDATORY_LABEL",			"SYSTEM_MANDATORY_LABEL_ACE_TYPE",		0x11),			# Integrity label
	"XA": ("CALLBACK_ACCESS_ALLOWED",	"ACCESS_ALLOWED_CALLBACK_ACE_TYPE",	0x09),			# Callback Access allowed
	"XD": ("CALLBACK_ACCESS_DENIED",	"ACCESS_DENIED_CALLBACK_ACE_TYPE",		0x0A),			# Callback Access denied
}

SDDL_FLAGS = {
	"CI" : ("CONTAINER_INHERIT", 	"CONTAINER_INHERIT_ACE",				0x02),		# Container inherit
	"OI" : ("OBJECT_INHERIT",    	"OBJECT_INHERIT_ACE",					0x01),		# Object inherit
	"NP" : ("NO_PROPAGATE",      	"NO_PROPAGATE_INHERIT_ACE",			0x04),		# Inherit no propagate
	"IO" : ("INHERIT_ONLY",      	"INHERIT_ONLY_ACE",					0x08),		# Inherit only
	"ID" : ("INHERITED",         	"INHERITED_ACE",						0x10),		# Inherited
	"SA" : ("AUDIT_SUCCESS",     	"SUCCESSFUL_ACCESS_ACE_FLAG",			0x40),		# Audit success
	"FA" : ("AUDIT_FAILURE",     	"FAILED_ACCESS_ACE_FLAG",				0x80),		# Audit failure
}

SDDL_RIGHTS = {
#-- Directory service object access rights:
	"CC" : ("CREATE_CHILD",		"ADS_RIGHT_DS_CREATE_CHILD",				0x00000001),
	"DC" : ("DELETE_CHILD",		"ADS_RIGHT_DS_DELETE_CHILD",				0x00000002),
	"LC" : ("LIST_CHILDREN",		"ADS_RIGHT_ACTRL_DS_LIST",					0x00000004),
	"SW" : ("SELF_WRITE",			"ADS_RIGHT_DS_SELF",						0x00000008),
	"RP" : ("READ_PROPERTY",		"ADS_RIGHT_DS_READ_PROP",					0x00000010),
	"WP" : ("WRITE_PROPERTY",		"ADS_RIGHT_DS_WRITE_PROP",					0x00000020),	# Read and execute?
	"DT" : ("DELETE_TREE",			"ADS_RIGHT_DS_DELETE_TREE",				0x00000040),
	"LO" : ("LIST_OBJECT",			"ADS_RIGHT_DS_LIST_OBJECT",				0x00000080),
	"CR" : ("CONTROL_ACCESS",		"ADS_RIGHT_DS_CONTROL_ACCESS",				0x00000100),
#-- Standard access rights:	
	"SD" : ("STANDARD_DELETE",		"ADS_RIGHT_DELETE",						0x00010000),
	"RC" : ("READ_CONTROL",		"ADS_RIGHT_READ_CONTROL",					0x00020000),
	"WD" : ("WRITE_DAC",			"ADS_RIGHT_WRITE_DAC",						0x00040000),
	"WO" : ("WRITE_OWNER",			"ADS_RIGHT_WRITE_OWNER",					0x00080000),
#-- Generic access rights	
	"GA" : ("GENERIC_ALL",			"ADS_RIGHT_GENERIC_ALL",					0x10000000),
	"GX" : ("GENERIC_EXECUTE",		"ADS_RIGHT_GENERIC_EXECUTE",				0x20000000),
	"GW" : ("GENERIC_WRITE",		"ADS_RIGHT_GENERIC_WRITE",					0x40000000),
	"GR" : ("GENERIC_READ",		"ADS_RIGHT_GENERIC_READ",					0x80000000),	
#-- File access rights:
	"FA" : ("FILE_ALL",				"FILE_ALL_ACCESS",							0x001F01FF), 			# (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)
	"FR" : ("FILE_READ",			"FILE_GENERIC_READ",						C_FILE_GENERIC_READ),   # 0x00120089
	"FW" : ("FILE_WRITE",			"FILE_GENERIC_WRITE",						C_FILE_GENERIC_WRITE),	# 0x00120116
	"FX" : ("FILE_EXECUTE",		"FILE_GENERIC_EXECUTE",					C_FILE_GENERIC_EXECUTE),# 0x001200A0
#-- Registry key access rights:
	"KA" : ("KEY_ALL",				"KEY_ALL_ACCESS",							0xF003F),
	"KR" : ("KEY_READ",				"KEY_READ",									0x20019),
	"KW" : ("KEY_WRITE",			"KEY_WRITE",								0x20006), # Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
	"KX" : ("KEY_EXECUTE",			"KEY_EXECUTE",								0x20019), # Equivalent to KEY_READ.
#-- Mandatory label rights:	
	"NW" : ("NO_WRITE_UP",			"SYSTEM_MANDATORY_LABEL_NO_READ_UP",		0x02),
	"NR" : ("NO_READ_UP",			"SYSTEM_MANDATORY_LABEL_NO_WRITE_UP",		0x01),
	"NX" : ("NO_EXECUTE_UP",		"SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP",	0x04),
}

SDDL_CMPST_RIGHTS = ['FA', 'FR', 'FW', 'FX', 'KA', 'KR', 'KW', 'KX']

SDDL_SIDS = {	# Well known SIDs
	"AN" : "ANONYMOUS",
	"AO" : "ACCOUNT_OPERATORS",
	"AU" : "AUTHENTICATED_USERS",
	"BA" : "BUILTIN_ADMINISTRATORS",
	"BG" : "BUILTIN_GUESTS",
	"BO" : "BACKUP_OPERATORS",
	"BU" : "BUILTIN_USERS",
	"CA" : "CERT_SERV_ADMINISTRATORS",
	"CD" : "CERTSVC_DCOM_ACCESS",
	"CG" : "CREATOR_GROUP",
	"CO" : "CREATOR_OWNER",
	"DA" : "DOMAIN_ADMINISTRATORS",
	"DC" : "DOMAIN_COMPUTERS",
	"DD" : "DOMAIN_DOMAIN_CONTROLLERS",
	"DG" : "DOMAIN_GUESTS",
	"DU" : "DOMAIN_USERS",
	"EA" : "ENTERPRISE_ADMINS",
	"ED" : "ENTERPRISE_DOMAIN_CONTROLLERS",
	"HI" : "ML_HIGH",
	"IU" : "INTERACTIVE",
	"LA" : "LOCAL_ADMIN",
	"LG" : "LOCAL_GUEST",
	"LS" : "LOCAL_SERVICE",
	"LW" : "ML_LOW",
	"ME" : "MLMEDIUM",
	"MU" : "PERFMON_USERS",
	"NO" : "NETWORK_CONFIGURATION_OPS",
	"NS" : "NETWORK_SERVICE",
	"NU" : "NETWORK",
	"PA" : "GROUP_POLICY_ADMINS",
	"PO" : "PRINTER_OPERATORS",
	"PS" : "PERSONAL_SELF",
	"PU" : "POWER_USERS",
	"RC" : "RESTRICTED_CODE",
	"RD" : "REMOTE_DESKTOP",
	"RE" : "REPLICATOR",
	"RO" : "ENTERPRISE_RO_DCs",
	"RS" : "RAS_SERVERS",
	"RU" : "ALIAS_PREW2KCOMPACC",
	"SA" : "SCHEMA_ADMINISTRATORS",
	"SI" : "ML_SYSTEM",
	"SO" : "SERVER_OPERATORS",
	"SU" : "SERVICE",
	"SY" : "LOCAL_SYSTEM",
	"WD" : "EVERYONE",
}

# ================================================== Read and parse SDDL procedures:

def parse_sddl(sddl):
	sddls = sddl.replace(')','').split('(')
	for i in range(len(sddls)):
		dl = sddls[i]
		if i == 0:
			dacl, flags = dl.split(':')
			print("  {} :: ".format(dl), end='')
			m = 0
			if re.match('^P', flags):
				print('SDDL_PROTECTED', end='')
				flags = flags[1::]
				m += 1
			if re.match('AR', flags):
				if m != 0: print(', ', end='')
				m += 1
				print('SDDL_AUTO_INHERIT_REQ', end='')
			if re.match('AI', flags):
				if m != 0: print(', ', end='')				
				m += 1
				print('SDDL_AUTO_INHERITED', end='')
			if m != 0:
				print()
		else:
			type, flags, rights, guid, iguid, sid = dl.split(';')
			print("  {:20}".format(dl))
			if len(sid) > 0:
				if sid in SDDL_SIDS: 
					sidname = SDDL_SIDS[sid]
				else:
					sidname = '<<sid>>'
				print('    {:30}'.format(sidname), end='')
			print('{:25} '.format(SDDL_TYPE[type][0]), end='')
			fl = ''
			if len(flags) > 0:							# flags
				for i in range(0, len(flags), 2):
					if len(fl) > 0: fl += '|'
					fl += SDDL_FLAGS[flags[i:i+2]][0]
			print('{:35} '.format(fl), end='')			# flags
			if len(rights) > 0:
				if rights in SDDL_RIGHTS:		  	 	# standars right abbreviation
					rs = SDDL_RIGHTS[rights][0]
				elif re.match('0x[0-9A-F]',rights): 	# hexadecimal right notation 
					toint = int(rights, 16)
					rs = ''
					for g in SDDL_CMPST_RIGHTS: 		# composite rights first
						mask = SDDL_RIGHTS[g][2]
						if (toint & mask) == mask:
							toint -= mask
							if len(rs) > 0:
								rs += '|'
							rs += SDDL_RIGHTS[g][0]
					while toint > 0:					# then parse with bitmask
						for r in SDDL_RIGHTS.values():
							if (toint & r[2]) == r[2]:
								toint -= r[2]
								if len(rs) > 0:
									rs += '|'
								rs += r[0]
				else:
					rs = 'non standard'
				print('{:16}'.format(rs), end='')
			print()

def show_file_sddl(filename): 
	line  = os.popen("cacls %s /s" % filename).read().replace('"','').split()[1]
	print("{} :: {}".format(filename, line))
	parse_sddl(line)

# ================================================== MAIN PROGRAM

if case == 1:
	show_file_sddl(filename)
elif case == 2:
	print("+++ Parse SDDL: {}".format(sddl))
	parse_sddl(sddl)
else:
	print("Something wrong.")

