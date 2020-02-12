# SDDL_Utils

* **readsddl** - tool for read and parse file ACLs in  SDDL format.
* **getsddl** - tool for get SDDL for specified file or folder.

## SYNOPSIS

1) Read and parse file ACLs in SDDL format:

       python readssdl.py [path]<filename>
	
2) Parse SDDL string:

       python readssdl.py /S:<SDDL>

3) Get SDDL representation ACL for file

       python getsddl.py <file | folder>

### Output:

1)

    README.md :: D:AI(A;ID;0x1301bf;;;AU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1301bf;;;BU)
      D:AI :: SDDL_AUTO_INHERITED
      A;ID;0x1301bf;;;AU  
        AUTHENTICATED_USERS           ACCESS_ALLOWED            INHERITED                           FILE_READ|DELETE_CHILD|LIST_CHILDREN|READ_PROPERTY|WRITE_PROPERTY|CONTROL_ACCESS|STANDARD_DELETE
      A;ID;FA;;;SY        
        LOCAL_SYSTEM                  ACCESS_ALLOWED            INHERITED                           FILE_ALL        
      A;ID;FA;;;BA        
        BUILTIN_ADMINISTRATORS        ACCESS_ALLOWED            INHERITED                           FILE_ALL        
      A;ID;0x1301bf;;;BU  
        BUILTIN_USERS                 ACCESS_ALLOWED            INHERITED                           FILE_READ|DELETE_CHILD|LIST_CHILDREN|READ_PROPERTY|WRITE_PROPERTY|CONTROL_ACCESS|STANDARD_DELETE
		
3) 

       D:AI(A;ID;0x1301bf;;;AU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1301bf;;;BU)
	
## Explanation	

First tool (readsddl) parse output of Windows standart CACLS tool.
But the second (getsddl) use direct call API procedures from Windows security module.
You may combine output of second tool as input for the first.

## Files:
	
* [readsddl.py](readsddl.py) - Tool for read and parse file ACLs in SDDL notation.
* [getsddl.py](getsddl.py) - Tool for read ACLs for specified file or folder (including network shares) and shown SDDL string representation of that.

## Requirements:

* Python
* Windows OS with NTFS

# AUTHOR
   An0ther0ne

# SEE ALSO:
* [ACE Strings](https://docs.microsoft.com/ru-ru/windows/win32/secauthz/ace-strings)
* [SID Strings](https://docs.microsoft.com/ru-ru/windows/win32/secauthz/sid-strings)
* [Security Descriptor Definition Language](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
* [Security Descriptor Definition Language for Conditional ACEs](https://docs.microsoft.com/ru-ru/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-)
* [Access Mask Format](https://docs.microsoft.com/ru-ru/windows/win32/secauthz/access-mask-format)
