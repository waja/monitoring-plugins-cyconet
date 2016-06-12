package Monitoring::GLPlugin::SNMP::MibsAndOids::CISCOENHANCEDMEMPOOLMIB;

$Monitoring::GLPlugin::SNMP::MibsAndOids::origin->{'CISCO-ENHANCED-MEMPOOL-MIB'} = {
  url => '',
  name => 'CISCO-ENHANCED-MEMPOOL-MIB',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::mib_ids->{'CISCO-ENHANCED-MEMPOOL-MIB'} =
  '1.3.6.1.4.1.9.9.221';

$Monitoring::GLPlugin::SNMP::MibsAndOids::mibs_and_oids->{'CISCO-ENHANCED-MEMPOOL-MIB'} = {
  ciscoEnhancedMemPoolMIB => '1.3.6.1.4.1.9.9.221',
  cempMIBNotifications => '1.3.6.1.4.1.9.9.221.0',
  cempMIBObjects => '1.3.6.1.4.1.9.9.221.1',
  cempMemPool => '1.3.6.1.4.1.9.9.221.1.1',
  cempMemPoolTable => '1.3.6.1.4.1.9.9.221.1.1.1',
  cempMemPoolEntry => '1.3.6.1.4.1.9.9.221.1.1.1.1',
  cempMemPoolIndex => '1.3.6.1.4.1.9.9.221.1.1.1.1.1',
  cempMemPoolType => '1.3.6.1.4.1.9.9.221.1.1.1.1.2',
  cempMemPoolTypeDefinition => 'CISCO-ENHANCED-MEMPOOL-MIB::CempMemPoolTypes',
  cempMemPoolName => '1.3.6.1.4.1.9.9.221.1.1.1.1.3',
  cempMemPoolPlatformMemory => '1.3.6.1.4.1.9.9.221.1.1.1.1.4',
  cempMemPoolAlternate => '1.3.6.1.4.1.9.9.221.1.1.1.1.5',
  cempMemPoolValid => '1.3.6.1.4.1.9.9.221.1.1.1.1.6',
  cempMemPoolUsed => '1.3.6.1.4.1.9.9.221.1.1.1.1.7',
  cempMemPoolFree => '1.3.6.1.4.1.9.9.221.1.1.1.1.8',
  cempMemPoolLargestFree => '1.3.6.1.4.1.9.9.221.1.1.1.1.9',
  cempMemPoolLowestFree => '1.3.6.1.4.1.9.9.221.1.1.1.1.10',
  cempMemPoolUsedLowWaterMark => '1.3.6.1.4.1.9.9.221.1.1.1.1.11',
  cempMemPoolAllocHit => '1.3.6.1.4.1.9.9.221.1.1.1.1.12',
  cempMemPoolAllocMiss => '1.3.6.1.4.1.9.9.221.1.1.1.1.13',
  cempMemPoolFreeHit => '1.3.6.1.4.1.9.9.221.1.1.1.1.14',
  cempMemPoolFreeMiss => '1.3.6.1.4.1.9.9.221.1.1.1.1.15',
  cempMemPoolShared => '1.3.6.1.4.1.9.9.221.1.1.1.1.16',
  cempMemPoolUsedOvrflw => '1.3.6.1.4.1.9.9.221.1.1.1.1.17',
  cempMemPoolHCUsed => '1.3.6.1.4.1.9.9.221.1.1.1.1.18',
  cempMemPoolFreeOvrflw => '1.3.6.1.4.1.9.9.221.1.1.1.1.19',
  cempMemPoolHCFree => '1.3.6.1.4.1.9.9.221.1.1.1.1.20',
  cempMemPoolLargestFreeOvrflw => '1.3.6.1.4.1.9.9.221.1.1.1.1.21',
  cempMemPoolHCLargestFree => '1.3.6.1.4.1.9.9.221.1.1.1.1.22',
  cempMemPoolLowestFreeOvrflw => '1.3.6.1.4.1.9.9.221.1.1.1.1.23',
  cempMemPoolHCLowestFree => '1.3.6.1.4.1.9.9.221.1.1.1.1.24',
  cempMemPoolUsedLowWaterMarkOvrflw => '1.3.6.1.4.1.9.9.221.1.1.1.1.25',
  cempMemPoolHCUsedLowWaterMark => '1.3.6.1.4.1.9.9.221.1.1.1.1.26',
  cempMemPoolSharedOvrflw => '1.3.6.1.4.1.9.9.221.1.1.1.1.27',
  cempMemPoolHCShared => '1.3.6.1.4.1.9.9.221.1.1.1.1.28',
  cempMemBufferPoolTable => '1.3.6.1.4.1.9.9.221.1.1.2',
  cempMemBufferPoolEntry => '1.3.6.1.4.1.9.9.221.1.1.2.1',
  cempMemBufferPoolIndex => '1.3.6.1.4.1.9.9.221.1.1.2.1.1',
  cempMemBufferMemPoolIndex => '1.3.6.1.4.1.9.9.221.1.1.2.1.2',
  cempMemBufferName => '1.3.6.1.4.1.9.9.221.1.1.2.1.3',
  cempMemBufferDynamic => '1.3.6.1.4.1.9.9.221.1.1.2.1.4',
  cempMemBufferSize => '1.3.6.1.4.1.9.9.221.1.1.2.1.5',
  cempMemBufferMin => '1.3.6.1.4.1.9.9.221.1.1.2.1.6',
  cempMemBufferMax => '1.3.6.1.4.1.9.9.221.1.1.2.1.7',
  cempMemBufferPermanent => '1.3.6.1.4.1.9.9.221.1.1.2.1.8',
  cempMemBufferTransient => '1.3.6.1.4.1.9.9.221.1.1.2.1.9',
  cempMemBufferTotal => '1.3.6.1.4.1.9.9.221.1.1.2.1.10',
  cempMemBufferFree => '1.3.6.1.4.1.9.9.221.1.1.2.1.11',
  cempMemBufferHit => '1.3.6.1.4.1.9.9.221.1.1.2.1.12',
  cempMemBufferMiss => '1.3.6.1.4.1.9.9.221.1.1.2.1.13',
  cempMemBufferFreeHit => '1.3.6.1.4.1.9.9.221.1.1.2.1.14',
  cempMemBufferFreeMiss => '1.3.6.1.4.1.9.9.221.1.1.2.1.15',
  cempMemBufferPermChange => '1.3.6.1.4.1.9.9.221.1.1.2.1.16',
  cempMemBufferPeak => '1.3.6.1.4.1.9.9.221.1.1.2.1.17',
  cempMemBufferPeakTime => '1.3.6.1.4.1.9.9.221.1.1.2.1.18',
  cempMemBufferTrim => '1.3.6.1.4.1.9.9.221.1.1.2.1.19',
  cempMemBufferGrow => '1.3.6.1.4.1.9.9.221.1.1.2.1.20',
  cempMemBufferFailures => '1.3.6.1.4.1.9.9.221.1.1.2.1.21',
  cempMemBufferNoStorage => '1.3.6.1.4.1.9.9.221.1.1.2.1.22',
  cempMemBufferCachePoolTable => '1.3.6.1.4.1.9.9.221.1.1.3',
  cempMemBufferCachePoolEntry => '1.3.6.1.4.1.9.9.221.1.1.3.1',
  cempMemBufferCacheSize => '1.3.6.1.4.1.9.9.221.1.1.3.1.1',
  cempMemBufferCacheTotal => '1.3.6.1.4.1.9.9.221.1.1.3.1.2',
  cempMemBufferCacheUsed => '1.3.6.1.4.1.9.9.221.1.1.3.1.3',
  cempMemBufferCacheHit => '1.3.6.1.4.1.9.9.221.1.1.3.1.4',
  cempMemBufferCacheMiss => '1.3.6.1.4.1.9.9.221.1.1.3.1.5',
  cempMemBufferCacheThreshold => '1.3.6.1.4.1.9.9.221.1.1.3.1.6',
  cempMemBufferCacheThresholdCount => '1.3.6.1.4.1.9.9.221.1.1.3.1.7',
  cempNotificationConfig => '1.3.6.1.4.1.9.9.221.1.2',
  cempMemBufferNotifyEnabled => '1.3.6.1.4.1.9.9.221.1.2.1',
  cempMIBConformance => '1.3.6.1.4.1.9.9.221.3',
  cempMIBCompliances => '1.3.6.1.4.1.9.9.221.3.1',
  cempMIBGroups => '1.3.6.1.4.1.9.9.221.3.2',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::definitions->{'CISCO-ENHANCED-MEMPOOL-MIB'} = {
  CempMemPoolTypes => {
    '1' => 'other',
    '2' => 'processorMemory',
    '3' => 'ioMemory',
    '4' => 'pciMemory',
    '5' => 'fastMemory',
    '6' => 'multibusMemory',
    '7' => 'interruptStackMemory',
    '8' => 'processStackMemory',
    '9' => 'localExceptionMemory',
    '10' => 'virtualMemory',
    '11' => 'reservedMemory',
    '12' => 'imageMemory',
    '13' => 'asicMemory',
    '14' => 'posixMemory',
  },
};
