package Monitoring::GLPlugin::SNMP::MibsAndOids::CISCOPROCESSMIB;

$Monitoring::GLPlugin::SNMP::MibsAndOids::origin->{'CISCO-PROCESS-MIB'} = {
  url => '',
  name => 'CISCO-PROCESS-MIB',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::mib_ids->{'CISCO-PROCESS-MIB'} =
    '1.3.6.1.4.1.9.9.109';

$Monitoring::GLPlugin::SNMP::MibsAndOids::mibs_and_oids->{'CISCO-PROCESS-MIB'} = {
  'ciscoProcessMIB' => '1.3.6.1.4.1.9.9.109',
  'ciscoProcessMIBObjects' => '1.3.6.1.4.1.9.9.109.1',
  'cpmCPU' => '1.3.6.1.4.1.9.9.109.1.1',
  'cpmCPUTotalTable' => '1.3.6.1.4.1.9.9.109.1.1.1',
  'cpmCPUTotalEntry' => '1.3.6.1.4.1.9.9.109.1.1.1.1',
  'cpmCPUTotalIndex' => '1.3.6.1.4.1.9.9.109.1.1.1.1.1',
  'cpmCPUTotalPhysicalIndex' => '1.3.6.1.4.1.9.9.109.1.1.1.1.2',
  'cpmCPUTotal5sec' => '1.3.6.1.4.1.9.9.109.1.1.1.1.3',
  'cpmCPUTotal1min' => '1.3.6.1.4.1.9.9.109.1.1.1.1.4',
  'cpmCPUTotal5min' => '1.3.6.1.4.1.9.9.109.1.1.1.1.5',
  'cpmCPUTotal5secRev' => '1.3.6.1.4.1.9.9.109.1.1.1.1.6',
  'cpmCPUTotal1minRev' => '1.3.6.1.4.1.9.9.109.1.1.1.1.7',
  'cpmCPUTotal5minRev' => '1.3.6.1.4.1.9.9.109.1.1.1.1.8',
  'cpmCPUMonInterval' => '1.3.6.1.4.1.9.9.109.1.1.1.1.9',
  'cpmCPUTotalMonIntervalValue' => '1.3.6.1.4.1.9.9.109.1.1.1.1.10',
  'cpmCPUInterruptMonIntervalValue' => '1.3.6.1.4.1.9.9.109.1.1.1.1.11',
  'cpmCPUMemoryUsed' => '1.3.6.1.4.1.9.9.109.1.1.1.1.12',
  'cpmCPUMemoryFree' => '1.3.6.1.4.1.9.9.109.1.1.1.1.13',
  'cpmCPUMemoryKernelReserved' => '1.3.6.1.4.1.9.9.109.1.1.1.1.14',
  'cpmCPUMemoryLowest' => '1.3.6.1.4.1.9.9.109.1.1.1.1.15',
  'cpmCPUMemoryUsedOvrflw' => '1.3.6.1.4.1.9.9.109.1.1.1.1.16',
  'cpmCPUMemoryHCUsed' => '1.3.6.1.4.1.9.9.109.1.1.1.1.17',
  'cpmCPUMemoryFreeOvrflw' => '1.3.6.1.4.1.9.9.109.1.1.1.1.18',
  'cpmCPUMemoryHCFree' => '1.3.6.1.4.1.9.9.109.1.1.1.1.19',
  'cpmCPUMemoryKernelReservedOvrflw' => '1.3.6.1.4.1.9.9.109.1.1.1.1.20',
  'cpmCPUMemoryHCKernelReserved' => '1.3.6.1.4.1.9.9.109.1.1.1.1.21',
  'cpmCPUMemoryLowestOvrflw' => '1.3.6.1.4.1.9.9.109.1.1.1.1.22',
  'cpmCPUMemoryHCLowest' => '1.3.6.1.4.1.9.9.109.1.1.1.1.23',
  'cpmCPULoadAvg1min' => '1.3.6.1.4.1.9.9.109.1.1.1.1.24',
  'cpmCPULoadAvg5min' => '1.3.6.1.4.1.9.9.109.1.1.1.1.25',
  'cpmCPULoadAvg15min' => '1.3.6.1.4.1.9.9.109.1.1.1.1.26',
  'cpmCPUMemoryCommitted' => '1.3.6.1.4.1.9.9.109.1.1.1.1.27',
  'cpmCPUMemoryCommittedOvrflw' => '1.3.6.1.4.1.9.9.109.1.1.1.1.28',
  'cpmCPUMemoryHCCommitted' => '1.3.6.1.4.1.9.9.109.1.1.1.1.29',
  'cpmCoreTable' => '1.3.6.1.4.1.9.9.109.1.1.2',
  'cpmCoreEntry' => '1.3.6.1.4.1.9.9.109.1.1.2.1',
  'cpmCoreIndex' => '1.3.6.1.4.1.9.9.109.1.1.2.1.1',
  'cpmCorePhysicalIndex' => '1.3.6.1.4.1.9.9.109.1.1.2.1.2',
  'cpmCore5sec' => '1.3.6.1.4.1.9.9.109.1.1.2.1.3',
  'cpmCore1min' => '1.3.6.1.4.1.9.9.109.1.1.2.1.4',
  'cpmCore5min' => '1.3.6.1.4.1.9.9.109.1.1.2.1.5',
  'cpmCoreLoadAvg1min' => '1.3.6.1.4.1.9.9.109.1.1.2.1.6',
  'cpmCoreLoadAvg5min' => '1.3.6.1.4.1.9.9.109.1.1.2.1.7',
  'cpmCoreLoadAvg15min' => '1.3.6.1.4.1.9.9.109.1.1.2.1.8',
  'cpmProcess' => '1.3.6.1.4.1.9.9.109.1.2',
  'cpmProcessTable' => '1.3.6.1.4.1.9.9.109.1.2.1',
  'cpmProcessEntry' => '1.3.6.1.4.1.9.9.109.1.2.1.1',
  'cpmProcessPID' => '1.3.6.1.4.1.9.9.109.1.2.1.1.1',
  'cpmProcessName' => '1.3.6.1.4.1.9.9.109.1.2.1.1.2',
  'cpmProcessuSecs' => '1.3.6.1.4.1.9.9.109.1.2.1.1.4',
  'cpmProcessTimeCreated' => '1.3.6.1.4.1.9.9.109.1.2.1.1.5',
  'cpmProcessAverageUSecs' => '1.3.6.1.4.1.9.9.109.1.2.1.1.6',
  'cpmProcessExtTable' => '1.3.6.1.4.1.9.9.109.1.2.2',
  'cpmProcessExtEntry' => '1.3.6.1.4.1.9.9.109.1.2.2.1',
  'cpmProcExtMemAllocated' => '1.3.6.1.4.1.9.9.109.1.2.2.1.1',
  'cpmProcExtMemFreed' => '1.3.6.1.4.1.9.9.109.1.2.2.1.2',
  'cpmProcExtInvoked' => '1.3.6.1.4.1.9.9.109.1.2.2.1.3',
  'cpmProcExtRuntime' => '1.3.6.1.4.1.9.9.109.1.2.2.1.4',
  'cpmProcExtUtil5Sec' => '1.3.6.1.4.1.9.9.109.1.2.2.1.5',
  'cpmProcExtUtil1Min' => '1.3.6.1.4.1.9.9.109.1.2.2.1.6',
  'cpmProcExtUtil5Min' => '1.3.6.1.4.1.9.9.109.1.2.2.1.7',
  'cpmProcExtPriority' => '1.3.6.1.4.1.9.9.109.1.2.2.1.8',
  'cpmProcExtPriorityDefinition' => 'CISCO-PROCESS-MIB::cpmProcExtPriority',
  'cpmProcessExtRevTable' => '1.3.6.1.4.1.9.9.109.1.2.3',
  'cpmProcessExtRevEntry' => '1.3.6.1.4.1.9.9.109.1.2.3.1',
  'cpmProcExtMemAllocatedRev' => '1.3.6.1.4.1.9.9.109.1.2.3.1.1',
  'cpmProcExtMemFreedRev' => '1.3.6.1.4.1.9.9.109.1.2.3.1.2',
  'cpmProcExtInvokedRev' => '1.3.6.1.4.1.9.9.109.1.2.3.1.3',
  'cpmProcExtRuntimeRev' => '1.3.6.1.4.1.9.9.109.1.2.3.1.4',
  'cpmProcExtUtil5SecRev' => '1.3.6.1.4.1.9.9.109.1.2.3.1.5',
  'cpmProcExtUtil1MinRev' => '1.3.6.1.4.1.9.9.109.1.2.3.1.6',
  'cpmProcExtUtil5MinRev' => '1.3.6.1.4.1.9.9.109.1.2.3.1.7',
  'cpmProcExtPriorityRev' => '1.3.6.1.4.1.9.9.109.1.2.3.1.8',
  'cpmProcExtPriorityRevDefinition' => 'CISCO-PROCESS-MIB::cpmProcExtPriorityRev',
  'cpmProcessType' => '1.3.6.1.4.1.9.9.109.1.2.3.1.9',
  'cpmProcessTypeDefinition' => 'CISCO-PROCESS-MIB::cpmProcessType',
  'cpmProcessRespawn' => '1.3.6.1.4.1.9.9.109.1.2.3.1.10',
  'cpmProcessRespawnCount' => '1.3.6.1.4.1.9.9.109.1.2.3.1.11',
  'cpmProcessRespawnAfterLastPatch' => '1.3.6.1.4.1.9.9.109.1.2.3.1.12',
  'cpmProcessMemoryCore' => '1.3.6.1.4.1.9.9.109.1.2.3.1.13',
  'cpmProcessMemoryCoreDefinition' => 'CISCO-PROCESS-MIB::cpmProcessMemoryCore',
  'cpmProcessLastRestartUser' => '1.3.6.1.4.1.9.9.109.1.2.3.1.14',
  'cpmProcessTextSegmentSize' => '1.3.6.1.4.1.9.9.109.1.2.3.1.15',
  'cpmProcessDataSegmentSize' => '1.3.6.1.4.1.9.9.109.1.2.3.1.16',
  'cpmProcessStackSize' => '1.3.6.1.4.1.9.9.109.1.2.3.1.17',
  'cpmProcessDynamicMemorySize' => '1.3.6.1.4.1.9.9.109.1.2.3.1.18',
  'cpmProcExtMemAllocatedRevOvrflw' => '1.3.6.1.4.1.9.9.109.1.2.3.1.19',
  'cpmProcExtHCMemAllocatedRev' => '1.3.6.1.4.1.9.9.109.1.2.3.1.20',
  'cpmProcExtMemFreedRevOvrflw' => '1.3.6.1.4.1.9.9.109.1.2.3.1.21',
  'cpmProcExtHCMemFreedRev' => '1.3.6.1.4.1.9.9.109.1.2.3.1.22',
  'cpmProcessTextSegmentSizeOvrflw' => '1.3.6.1.4.1.9.9.109.1.2.3.1.23',
  'cpmProcessHCTextSegmentSize' => '1.3.6.1.4.1.9.9.109.1.2.3.1.24',
  'cpmProcessDataSegmentSizeOvrflw' => '1.3.6.1.4.1.9.9.109.1.2.3.1.25',
  'cpmProcessHCDataSegmentSize' => '1.3.6.1.4.1.9.9.109.1.2.3.1.26',
  'cpmProcessStackSizeOvrflw' => '1.3.6.1.4.1.9.9.109.1.2.3.1.27',
  'cpmProcessHCStackSize' => '1.3.6.1.4.1.9.9.109.1.2.3.1.28',
  'cpmProcessDynamicMemorySizeOvrflw' => '1.3.6.1.4.1.9.9.109.1.2.3.1.29',
  'cpmProcessHCDynamicMemorySize' => '1.3.6.1.4.1.9.9.109.1.2.3.1.30',
  'cpmCPUThresholdTable' => '1.3.6.1.4.1.9.9.109.1.2.4',
  'cpmCPUThresholdEntry' => '1.3.6.1.4.1.9.9.109.1.2.4.1',
  'cpmCPUThresholdClass' => '1.3.6.1.4.1.9.9.109.1.2.4.1.1',
  'cpmCPUThresholdClassDefinition' => 'CISCO-PROCESS-MIB::cpmCPUThresholdClass',
  'cpmCPURisingThresholdValue' => '1.3.6.1.4.1.9.9.109.1.2.4.1.2',
  'cpmCPURisingThresholdPeriod' => '1.3.6.1.4.1.9.9.109.1.2.4.1.3',
  'cpmCPUFallingThresholdValue' => '1.3.6.1.4.1.9.9.109.1.2.4.1.4',
  'cpmCPUFallingThresholdPeriod' => '1.3.6.1.4.1.9.9.109.1.2.4.1.5',
  'cpmCPUThresholdEntryStatus' => '1.3.6.1.4.1.9.9.109.1.2.4.1.6',
  'cpmCPUHistory' => '1.3.6.1.4.1.9.9.109.1.2.5',
  'cpmCPUHistoryThreshold' => '1.3.6.1.4.1.9.9.109.1.2.5.1',
  'cpmCPUHistorySize' => '1.3.6.1.4.1.9.9.109.1.2.5.2',
  'cpmCPUHistoryTable' => '1.3.6.1.4.1.9.9.109.1.2.5.3',
  'cpmCPUHistoryEntry' => '1.3.6.1.4.1.9.9.109.1.2.5.3.1',
  'cpmCPUHistoryReportId' => '1.3.6.1.4.1.9.9.109.1.2.5.3.1.1',
  'cpmCPUHistoryReportSize' => '1.3.6.1.4.1.9.9.109.1.2.5.3.1.2',
  'cpmCPUHistoryTotalUtil' => '1.3.6.1.4.1.9.9.109.1.2.5.3.1.3',
  'cpmCPUHistoryInterruptUtil' => '1.3.6.1.4.1.9.9.109.1.2.5.3.1.4',
  'cpmCPUHistoryCreatedTime' => '1.3.6.1.4.1.9.9.109.1.2.5.3.1.5',
  'cpmCPUProcessHistoryTable' => '1.3.6.1.4.1.9.9.109.1.2.5.4',
  'cpmCPUProcessHistoryEntry' => '1.3.6.1.4.1.9.9.109.1.2.5.4.1',
  'cpmCPUProcessHistoryIndex' => '1.3.6.1.4.1.9.9.109.1.2.5.4.1.1',
  'cpmCPUHistoryProcId' => '1.3.6.1.4.1.9.9.109.1.2.5.4.1.2',
  'cpmCPUHistoryProcName' => '1.3.6.1.4.1.9.9.109.1.2.5.4.1.3',
  'cpmCPUHistoryProcCreated' => '1.3.6.1.4.1.9.9.109.1.2.5.4.1.4',
  'cpmCPUHistoryProcUtil' => '1.3.6.1.4.1.9.9.109.1.2.5.4.1.5',
  'cpmThread' => '1.3.6.1.4.1.9.9.109.1.3',
  'cpmThreadTable' => '1.3.6.1.4.1.9.9.109.1.3.1',
  'cpmThreadEntry' => '1.3.6.1.4.1.9.9.109.1.3.1.1',
  'cpmThreadID' => '1.3.6.1.4.1.9.9.109.1.3.1.1.1',
  'cpmThreadName' => '1.3.6.1.4.1.9.9.109.1.3.1.1.2',
  'cpmThreadPriority' => '1.3.6.1.4.1.9.9.109.1.3.1.1.3',
  'cpmThreadState' => '1.3.6.1.4.1.9.9.109.1.3.1.1.4',
  'cpmThreadStateDefinition' => 'CISCO-PROCESS-MIB::cpmThreadState',
  'cpmThreadBlockingProcess' => '1.3.6.1.4.1.9.9.109.1.3.1.1.5',
  'cpmThreadCpuUtilization' => '1.3.6.1.4.1.9.9.109.1.3.1.1.6',
  'cpmThreadStackSize' => '1.3.6.1.4.1.9.9.109.1.3.1.1.7',
  'cpmThreadStackSizeOvrflw' => '1.3.6.1.4.1.9.9.109.1.3.1.1.8',
  'cpmThreadHCStackSize' => '1.3.6.1.4.1.9.9.109.1.3.1.1.9',
  'cpmVirtualProcess' => '1.3.6.1.4.1.9.9.109.1.4',
  'cpmVirtualProcessTable' => '1.3.6.1.4.1.9.9.109.1.4.1',
  'cpmVirtualProcessEntry' => '1.3.6.1.4.1.9.9.109.1.4.1.1',
  'cpmVirtualProcessID' => '1.3.6.1.4.1.9.9.109.1.4.1.1.1',
  'cpmVirtualProcessName' => '1.3.6.1.4.1.9.9.109.1.4.1.1.2',
  'cpmVirtualProcessUtil5Sec' => '1.3.6.1.4.1.9.9.109.1.4.1.1.3',
  'cpmVirtualProcessUtil1Min' => '1.3.6.1.4.1.9.9.109.1.4.1.1.4',
  'cpmVirtualProcessUtil5Min' => '1.3.6.1.4.1.9.9.109.1.4.1.1.5',
  'cpmVirtualProcessMemAllocated' => '1.3.6.1.4.1.9.9.109.1.4.1.1.6',
  'cpmVirtualProcessMemFreed' => '1.3.6.1.4.1.9.9.109.1.4.1.1.7',
  'cpmVirtualProcessInvokeCount' => '1.3.6.1.4.1.9.9.109.1.4.1.1.8',
  'cpmVirtualProcessRuntime' => '1.3.6.1.4.1.9.9.109.1.4.1.1.9',
  'cpmVirtualProcessMemAllocatedOvrflw' => '1.3.6.1.4.1.9.9.109.1.4.1.1.10',
  'cpmVirtualProcessHCMemAllocated' => '1.3.6.1.4.1.9.9.109.1.4.1.1.11',
  'cpmVirtualProcessMemFreedOvrflw' => '1.3.6.1.4.1.9.9.109.1.4.1.1.12',
  'cpmVirtualProcessHCMemFreed' => '1.3.6.1.4.1.9.9.109.1.4.1.1.13',
  'ciscoProcessMIBNotifPrefix' => '1.3.6.1.4.1.9.9.109.2',
  'ciscoProcessMIBNotifs' => '1.3.6.1.4.1.9.9.109.2.0',
  'ciscoProcessMIBConformance' => '1.3.6.1.4.1.9.9.109.3',
  'cpmCompliances' => '1.3.6.1.4.1.9.9.109.3.1',
  'cpmGroups' => '1.3.6.1.4.1.9.9.109.3.2',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::definitions->{'CISCO-PROCESS-MIB'} = {
  'cpmThreadState' => {
    '1' => 'other',
    '2' => 'dead',
    '3' => 'running',
    '4' => 'ready',
    '5' => 'stopped',
    '6' => 'send',
    '7' => 'receive',
    '8' => 'reply',
    '9' => 'stack',
    '10' => 'waitpage',
    '11' => 'sigsuspend',
    '12' => 'sigwaitinfo',
    '13' => 'nanosleep',
    '14' => 'mutex',
    '15' => 'condvar',
    '16' => 'join',
    '17' => 'intr',
    '18' => 'sem',
  },
  'cpmProcExtPriority' => {
    '1' => 'critical',
    '2' => 'high',
    '3' => 'normal',
    '4' => 'low',
    '5' => 'notAssigned',
  },
  'cpmProcExtPriorityRev' => {
    '1' => 'critical',
    '2' => 'high',
    '3' => 'normal',
    '4' => 'low',
    '5' => 'notAssigned',
  },
  'cpmProcessType' => {
    '1' => 'other',
    '2' => 'posix',
    '3' => 'ios',
  },
  'cpmProcessMemoryCore' => {
    '1' => 'other',
    '2' => 'mainmem',
    '3' => 'mainmemSharedmem',
    '4' => 'mainmemText',
    '5' => 'mainmemTextSharedmem',
    '6' => 'sharedmem',
    '7' => 'sparse',
    '8' => 'off',
  },
  'cpmCPUThresholdClass' => {
    '1' => 'total',
    '2' => 'interrupt',
    '3' => 'process',
  },
};