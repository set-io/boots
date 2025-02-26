package machine

import (
	"fmt"
	"os"
)

//go:generate stringer -type=Cap
type Cap uint8

const (
	CapIRQChip                  Cap = 0
	CapHLT                      Cap = 1
	CapMMUShadowCacheControl    Cap = 2
	CapUserMemory               Cap = 3
	CapSetTSSAddr               Cap = 4
	CapVAPIC                    Cap = 6
	CapEXTCPUID                 Cap = 7
	CapClockSource              Cap = 8
	CapNRVCPUS                  Cap = 9  /* returns recommended max vcpus per vm */
	CapNRMemSlots               Cap = 10 /* returns max memory slots per vm */
	CapPIT                      Cap = 11
	CapNopIODelay               Cap = 12
	CapPVMMU                    Cap = 13
	CapMPState                  Cap = 14
	CapCoalescedMMIO            Cap = 15
	CapSyncMMU                  Cap = 16 /* Changes to host mmap are reflected in guest */
	CapIOMMU                    Cap = 18
	CapDestroyMemoryRegionWorks Cap = 21
	CapUserNMI                  Cap = 22
	CapSetGuestDebug            Cap = 23
	CapReinjectControl          Cap = 24
	CapIRQRouting               Cap = 25
	CapIRQInjectStatus          Cap = 26
	CapAssignDevIRQ             Cap = 29
	CapJoinMemoryRegionsWorks   Cap = 30
	CapMCE                      Cap = 31
	CapIRQFD                    Cap = 32
	CapPIT2                     Cap = 33
	CapSetBootCPUID             Cap = 34
	CapPITState2                Cap = 35
	CapIOEventFD                Cap = 36
	CapSetIdentityMapAddr       Cap = 37
	CapXENHVM                   Cap = 38
	CapAdjustClock              Cap = 39
	CapInternalErrorData        Cap = 40
	CapVCPUEvents               Cap = 41
	CapS390PSW                  Cap = 42
	CapPPCSegState              Cap = 43
	CapHyperV                   Cap = 44
	CapHyperVVAPIC              Cap = 45
	CapHyperVSPIN               Cap = 46
	CapPCISEgment               Cap = 47
	CapPPCPairedSingles         Cap = 48
	CapINTRShadow               Cap = 49
	CapDebugRegs                Cap = 50
	CapX86RobustSinglestep      Cap = 51
	CapPPCOSI                   Cap = 52
	CapPPCUnsetIRQ              Cap = 53
	CapEnableCap                Cap = 54
	CapXSave                    Cap = 55
	CapXCRS                     Cap = 56
	CapPPCGetPVInfo             Cap = 57
	CapPPCIRQLevel              Cap = 58
	CapASYNCPF                  Cap = 59
	CapTSCControl               Cap = 60
	CapGetTSCkHz                Cap = 61
	CapPPCBookeSREGS            Cap = 62
	CapSPAPRTCE                 Cap = 63
	CapPPCSMT                   Cap = 64
	CapPPCRMA                   Cap = 65
	CapMAXVCPUS                 Cap = 66 /* returns max vcpus per vm */
	CapPPCHIOR                  Cap = 67
	CapPPCPAPR                  Cap = 68
	CapSWTLB                    Cap = 69
	CapONEREG                   Cap = 70
	CapS390GMap                 Cap = 71
	CapTSCDeadlineTimer         Cap = 72
	CapS390UControl             Cap = 73
	CapSyncRegs                 Cap = 74
	CapPCI23                    Cap = 75
	CapKVMClockCtrl             Cap = 76
	CapSignalMSI                Cap = 77
	CapPPCGetSMMUInfo           Cap = 78
	CapS390COW                  Cap = 79
	CapPPCAllocHTAB             Cap = 80
	CapReadOnlyMEM              Cap = 81
	CapIRQFDResample            Cap = 82
	CapPPCBokkeWatchdog         Cap = 83
	CapPPCHTABFD                Cap = 84
	CapS390CSSSupport           Cap = 85
	CapPPCEPR                   Cap = 86
	CapARMPSCI                  Cap = 87
	CapARMSetDeviceAddr         Cap = 88
	CapDeviceCtrl               Cap = 89
	CapIRQMPIC                  Cap = 90
	CapPPCRTAS                  Cap = 91
	CapIRQXICS                  Cap = 92
	CapARMEL132BIT              Cap = 93
	CapSPAPRMultiTCE            Cap = 94
	CapEXTEmulCPUID             Cap = 95
	CapHyperVTIME               Cap = 96
	CapIOAPICPolarityIgnored    Cap = 97
	CapEnableCAPVM              Cap = 98
	CapS390IRQCHIP              Cap = 99
	CapIOEVENTFDNoLength        Cap = 100
	CapVMAttributes             Cap = 101
	CapARMPSCI02                Cap = 102
	CapPPCFixupHCALL            Cap = 103
	CapPPCEnableHCALL           Cap = 104
	CapCheckExtentionVM         Cap = 105
	CapS390UserSIGP             Cap = 106
	CapS390VectorRegisters      Cap = 107
	CapS390MemOp                Cap = 108
	CapS390UserSTSI             Cap = 109
	CapS390SKEYS                Cap = 110
	CapMIPSFPU                  Cap = 111
	CapMIPSMSA                  Cap = 112
	CapS390InjectIRQ            Cap = 113
	CapS390IRQState             Cap = 114
	CapPPCHWRNG                 Cap = 115
	CapDisableQuirks            Cap = 116
	CapX86SMM                   Cap = 117
	CapMultiAddressSpace        Cap = 118
	CapGuestDebugHWBPS          Cap = 119
	CapGuestDebugHWWPS          Cap = 120
	CapSplitIRQChip             Cap = 121
	CapIOEventFDAnyLength       Cap = 122
	CapHyperVSYNIC              Cap = 123
	CapS390RI                   Cap = 124
	CapSPAPRTCE64               Cap = 125
	CapARMPMUV3                 Cap = 126
	CapVCPUAttributes           Cap = 127
	CapMAXVCPUID                Cap = 128
	CapX2APICAPI                Cap = 129
	CapS390UserINSTR0           Cap = 130
	CapMSIDEVID                 Cap = 131
	CapPPCHTM                   Cap = 132
	CapSPAPRResizeHPT           Cap = 133
	CapPPCMMURADIX              Cap = 134
	CapPPCMMUHASHV3             Cap = 135
	CapImmediateExit            Cap = 136
	CapMIPSVZ                   Cap = 137
	CapMIPSTE                   Cap = 138
	CapMIPS64BIT                Cap = 139
	CapS390GS                   Cap = 140
	CapS390AIS                  Cap = 141
	CapSPAPRTCEVFIO             Cap = 142
	CapX86DisableExits          Cap = 143
	CapARMUserIRQ               Cap = 144
	CapS390CMMAMigration        Cap = 145
	CapPPCFWNMI                 Cap = 146
	CapPPCSMTPossible           Cap = 147
	CapHyperVSYNIC2             Cap = 148
	CapHyperVVPIndex            Cap = 149
	CapS390AISMigration         Cap = 150
	CapPPCGetCPUChar            Cap = 151
	CapS390BPB                  Cap = 152
	CapGETMSRFeatures           Cap = 153
	CapHyperVEventFD            Cap = 154
	CapHyperVTLBFlush           Cap = 155
	CapS390HPage1M              Cap = 156
	CapNestedState              Cap = 157
	CapARMInjectSErrorESR       Cap = 158
	CapMSRPlatformInfo          Cap = 159
	CapPPCNestedHV              Cap = 160
	CapHyperVSendIPI            Cap = 161
	CapCoalescedPIO             Cap = 162
	CapHyperVEnlightenedVMCS    Cap = 163
	CapExceptionPayload         Cap = 164
	CapARMVMIPASize             Cap = 165
	CapManualDirtyLogProtect    Cap = 166 /* Obsolete */
	CapHyerVCPUID               Cap = 167
	CapManualDirtyLogProtect2   Cap = 168
	CapPPCIRQXive               Cap = 169
	CapARMSVE                   Cap = 170
	CapARMPTRAuthAddress        Cap = 171
	CapARMPTRAuthGeneric        Cap = 172
	CapPMUEventFilter           Cap = 173
	CapARMIRQLineLayout2        Cap = 174
	CapHyperVDirectTLBFlush     Cap = 175
	CapPPCGuestDebugSStep       Cap = 176
	CapARMNISVToUser            Cap = 177
	CapARMInjectEXTDABT         Cap = 178
	CapS390VCPUResets           Cap = 179
	CapS390Protected            Cap = 180
	CapPPCSecureGuest           Cap = 181
	CapHALTPoll                 Cap = 182
	CapASYNCPFInt               Cap = 183
	CapLastCPU                  Cap = 184
	CapSmallerMaxPhyAddr        Cap = 185
	CapS390DIAG318              Cap = 186
	CapStealTime                Cap = 187
	CapX86UserSpaceMSR          Cap = 188
	CapX86MSRFilter             Cap = 189
	CapEnforcePVFeatureCPUID    Cap = 190
	CapSysHyperVCPUID           Cap = 191
	CapDirtyLogRing             Cap = 192
	CapX86BusLockExit           Cap = 193
	CapPPCDAWR1                 Cap = 194
	CapSetGuestDebug2           Cap = 195
	CapSGXAttribute             Cap = 196
	CapVMCopyEncContextFrom     Cap = 197
	CapPTPKVM                   Cap = 198
	CapHyperVEnforceCPUID       Cap = 199
	CapSREGS2                   Cap = 200
	CapEXitHyperCall            Cap = 201
	CapPPCRPTInvalidate         Cap = 202
	CapBinaryStatsFD            Cap = 203
	CapExitOnEmulationFailure   Cap = 204
	CapARMMTE                   Cap = 205
	CapVMMoveEncContextFrom     Cap = 206
	CapVMGPABits                Cap = 207
	CapXSave2                   Cap = 208
	CapSysAttributes            Cap = 209
	CapPPCAILMode3              Cap = 210
	CapS390MemOpExtention       Cap = 211
	CapPMUCap                   Cap = 212
	CapDisableQuirks2           Cap = 213
	CapVMTSCControl             Cap = 214
	CapSystemEventData          Cap = 215
	CapARMSystemSuspend         Cap = 216
	CapS390ProtectedDump        Cap = 217
	CapX86TripleFaultEvent      Cap = 218
	CapX86NotifyVMExit          Cap = 219
	CapVMDisableNXHugePages     Cap = 220
	CapS390ZPCIOP               Cap = 221
	CapS390CPUTOPOLOGY          Cap = 222
	CapDirtyLogRingACQRel       Cap = 223
)

func KVMCapabilities() error {
	X86Items := []Cap{
		CapIRQChip,
		CapUserMemory,
		CapSetTSSAddr,
		CapEXTCPUID,
		CapMPState,
		CapCoalescedMMIO,
		CapUserNMI,
		CapSetGuestDebug,
		CapReinjectControl,
		CapIRQRouting,
		CapMCE,
		CapIRQFD,
		CapPIT2,
		CapSetBootCPUID,
		CapPITState2,
		CapIOEventFD,
		CapAdjustClock,
		CapVCPUEvents,
		CapINTRShadow,
		CapDebugRegs,
		CapEnableCap,
		CapXSave,
		CapXCRS,
		CapTSCControl,
		CapONEREG,
		CapKVMClockCtrl,
		CapSignalMSI,
		CapDeviceCtrl,
		CapEXTEmulCPUID,
		CapVMAttributes,
		CapX86SMM,
		CapX86DisableExits,
		CapGETMSRFeatures,
		CapNestedState,
		CapCoalescedPIO,
		CapManualDirtyLogProtect2,
		CapPMUEventFilter,
		CapX86UserSpaceMSR,
		CapX86MSRFilter,
		CapX86BusLockExit,
		CapSREGS2,
		CapBinaryStatsFD,
		CapXSave2,
		CapSysAttributes,
		CapVMTSCControl,
		CapX86TripleFaultEvent,
		CapX86NotifyVMExit,
	}

	ile, err := os.Open(kvmDev)
	if err != nil {
		return err
	}
	defer ile.Close()

	fd := ile.Fd()
	for _, item := range X86Items {
		res, err := CheckExtension(P(fd), item)
		if err != nil {
			return err
		}
		fmt.Printf("%-30s: %t\n", item, (res != 0))
	}
	return nil
}

func ProbeCPUID() error {
	kvmFile, err := os.Open(kvmDev)
	if err != nil {
		return err
	}
	defer kvmFile.Close()

	kvmFd := kvmFile.Fd()

	cpuid := CPUID{
		Nent:    100,
		Entries: make([]CPUIDEntry2, 100),
	}
	if err := GetSupportedCPUID(P(kvmFd), &cpuid); err != nil {
		return err
	}
	for _, e := range cpuid.Entries {
		fmt.Printf("0x%08x 0x%02x: eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x (flag:%x)\n",
			e.Function, e.Index, e.Eax, e.Ebx, e.Ecx, e.Edx, e.Flags)
	}
	return nil
}

func CheckExtension(kvmFd P, c Cap) (P, error) {
	return Ioctl(kvmFd, IIO(kvmCheckExtension), P(c))
}
