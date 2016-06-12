package Monitoring::GLPlugin::SNMP::MibsAndOids::CISCOCCMMIB;

$Monitoring::GLPlugin::SNMP::MibsAndOids::origin->{'CISCO-CCM-MIB'} = {
  url => '',
  name => 'CISCO-CCM-MIB',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::mibs_and_oids->{'CISCO-CCM-MIB'} = {
  'org' => '1.3',
  'dod' => '1.3.6',
  'internet' => '1.3.6.1',
  'directory' => '1.3.6.1.1',
  'mgmt' => '1.3.6.1.2',
  'experimental' => '1.3.6.1.3',
  'private' => '1.3.6.1.4',
  'enterprises' => '1.3.6.1.4.1',
  'cisco' => '1.3.6.1.4.1.9',
  'ciscoMgmt' => '1.3.6.1.4.1.9.9',
  'ciscoCcmMIB' => '1.3.6.1.4.1.9.9.156',
  'ciscoCcmMIBObjects' => '1.3.6.1.4.1.9.9.156.1',
  'ccmGeneralInfo' => '1.3.6.1.4.1.9.9.156.1.1',
  'ccmGroupTable' => '1.3.6.1.4.1.9.9.156.1.1.1',
  'ccmGroupEntry' => '1.3.6.1.4.1.9.9.156.1.1.1.1',
  'ccmGroupIndex' => '1.3.6.1.4.1.9.9.156.1.1.1.1.1',
  'ccmGroupName' => '1.3.6.1.4.1.9.9.156.1.1.1.1.2',
  'ccmGroupTftpDefault' => '1.3.6.1.4.1.9.9.156.1.1.1.1.3',
  'ccmTable' => '1.3.6.1.4.1.9.9.156.1.1.2',
  'ccmEntry' => '1.3.6.1.4.1.9.9.156.1.1.2.1',
  'ccmIndex' => '1.3.6.1.4.1.9.9.156.1.1.2.1.1',
  'ccmName' => '1.3.6.1.4.1.9.9.156.1.1.2.1.2',
  'ccmDescription' => '1.3.6.1.4.1.9.9.156.1.1.2.1.3',
  'ccmVersion' => '1.3.6.1.4.1.9.9.156.1.1.2.1.4',
  'ccmStatus' => '1.3.6.1.4.1.9.9.156.1.1.2.1.5',
  'ccmStatusDefinition' => {
    '1' => 'unknown',
    '2' => 'up',
    '3' => 'down',
  },
  'ccmInetAddressType' => '1.3.6.1.4.1.9.9.156.1.1.2.1.6',
  'ccmInetAddress' => '1.3.6.1.4.1.9.9.156.1.1.2.1.7',
  'ccmClusterId' => '1.3.6.1.4.1.9.9.156.1.1.2.1.8',
  'ccmInetAddress2Type' => '1.3.6.1.4.1.9.9.156.1.1.2.1.9',
  'ccmInetAddress2' => '1.3.6.1.4.1.9.9.156.1.1.2.1.10',
  'ccmGroupMappingTable' => '1.3.6.1.4.1.9.9.156.1.1.3',
  'ccmGroupMappingEntry' => '1.3.6.1.4.1.9.9.156.1.1.3.1',
  'ccmCMGroupMappingCMPriority' => '1.3.6.1.4.1.9.9.156.1.1.3.1.1',
  'ccmRegionTable' => '1.3.6.1.4.1.9.9.156.1.1.4',
  'ccmRegionEntry' => '1.3.6.1.4.1.9.9.156.1.1.4.1',
  'ccmRegionIndex' => '1.3.6.1.4.1.9.9.156.1.1.4.1.1',
  'ccmRegionName' => '1.3.6.1.4.1.9.9.156.1.1.4.1.2',
  'ccmRegionPairTable' => '1.3.6.1.4.1.9.9.156.1.1.5',
  'ccmRegionPairEntry' => '1.3.6.1.4.1.9.9.156.1.1.5.1',
  'ccmRegionSrcIndex' => '1.3.6.1.4.1.9.9.156.1.1.5.1.1',
  'ccmRegionDestIndex' => '1.3.6.1.4.1.9.9.156.1.1.5.1.2',
  'ccmRegionAvailableBandWidth' => '1.3.6.1.4.1.9.9.156.1.1.5.1.3',
  'ccmTimeZoneTable' => '1.3.6.1.4.1.9.9.156.1.1.6',
  'ccmTimeZoneEntry' => '1.3.6.1.4.1.9.9.156.1.1.6.1',
  'ccmTimeZoneIndex' => '1.3.6.1.4.1.9.9.156.1.1.6.1.1',
  'ccmTimeZoneName' => '1.3.6.1.4.1.9.9.156.1.1.6.1.2',
  'ccmTimeZoneOffset' => '1.3.6.1.4.1.9.9.156.1.1.6.1.3',
  'ccmTimeZoneOffsetHours' => '1.3.6.1.4.1.9.9.156.1.1.6.1.4',
  'ccmTimeZoneOffsetMinutes' => '1.3.6.1.4.1.9.9.156.1.1.6.1.5',
  'ccmDevicePoolTable' => '1.3.6.1.4.1.9.9.156.1.1.7',
  'ccmDevicePoolEntry' => '1.3.6.1.4.1.9.9.156.1.1.7.1',
  'ccmDevicePoolIndex' => '1.3.6.1.4.1.9.9.156.1.1.7.1.1',
  'ccmDevicePoolName' => '1.3.6.1.4.1.9.9.156.1.1.7.1.2',
  'ccmDevicePoolRegionIndex' => '1.3.6.1.4.1.9.9.156.1.1.7.1.3',
  'ccmDevicePoolTimeZoneIndex' => '1.3.6.1.4.1.9.9.156.1.1.7.1.4',
  'ccmDevicePoolGroupIndex' => '1.3.6.1.4.1.9.9.156.1.1.7.1.5',
  'ccmProductTypeTable' => '1.3.6.1.4.1.9.9.156.1.1.8',
  'ccmProductTypeEntry' => '1.3.6.1.4.1.9.9.156.1.1.8.1',
  'ccmProductTypeIndex' => '1.3.6.1.4.1.9.9.156.1.1.8.1.1',
  'ccmProductType' => '1.3.6.1.4.1.9.9.156.1.1.8.1.2',
  'ccmProductName' => '1.3.6.1.4.1.9.9.156.1.1.8.1.3',
  'ccmProductCategory' => '1.3.6.1.4.1.9.9.156.1.1.8.1.4',
  'ccmPhoneInfo' => '1.3.6.1.4.1.9.9.156.1.2',
  'ccmPhoneTable' => '1.3.6.1.4.1.9.9.156.1.2.1',
  'ccmPhoneEntry' => '1.3.6.1.4.1.9.9.156.1.2.1.1',
  'ccmPhoneIndex' => '1.3.6.1.4.1.9.9.156.1.2.1.1.1',
  'ccmPhonePhysicalAddress' => '1.3.6.1.4.1.9.9.156.1.2.1.1.2',
  'ccmPhoneType' => '1.3.6.1.4.1.9.9.156.1.2.1.1.3',
  'ccmPhoneDescription' => '1.3.6.1.4.1.9.9.156.1.2.1.1.4',
  'ccmPhoneUserName' => '1.3.6.1.4.1.9.9.156.1.2.1.1.5',
  'ccmPhoneIpAddress' => '1.3.6.1.4.1.9.9.156.1.2.1.1.6',
  'ccmPhoneStatus' => '1.3.6.1.4.1.9.9.156.1.2.1.1.7',
  'ccmPhoneTimeLastRegistered' => '1.3.6.1.4.1.9.9.156.1.2.1.1.8',
  'ccmPhoneE911Location' => '1.3.6.1.4.1.9.9.156.1.2.1.1.9',
  'ccmPhoneLoadID' => '1.3.6.1.4.1.9.9.156.1.2.1.1.10',
  'ccmPhoneLastError' => '1.3.6.1.4.1.9.9.156.1.2.1.1.11',
  'ccmPhoneTimeLastError' => '1.3.6.1.4.1.9.9.156.1.2.1.1.12',
  'ccmPhoneDevicePoolIndex' => '1.3.6.1.4.1.9.9.156.1.2.1.1.13',
  'ccmPhoneInetAddressType' => '1.3.6.1.4.1.9.9.156.1.2.1.1.14',
  'ccmPhoneInetAddress' => '1.3.6.1.4.1.9.9.156.1.2.1.1.15',
  'ccmPhoneStatusReason' => '1.3.6.1.4.1.9.9.156.1.2.1.1.16',
  'ccmPhoneTimeLastStatusUpdt' => '1.3.6.1.4.1.9.9.156.1.2.1.1.17',
  'ccmPhoneProductTypeIndex' => '1.3.6.1.4.1.9.9.156.1.2.1.1.18',
  'ccmPhoneProtocol' => '1.3.6.1.4.1.9.9.156.1.2.1.1.19',
  'ccmPhoneName' => '1.3.6.1.4.1.9.9.156.1.2.1.1.20',
  'ccmPhoneInetAddressIPv4' => '1.3.6.1.4.1.9.9.156.1.2.1.1.21',
  'ccmPhoneInetAddressIPv6' => '1.3.6.1.4.1.9.9.156.1.2.1.1.22',
  'ccmPhoneIPv4Attribute' => '1.3.6.1.4.1.9.9.156.1.2.1.1.23',
  'ccmPhoneIPv6Attribute' => '1.3.6.1.4.1.9.9.156.1.2.1.1.24',
  'ccmPhoneActiveLoadID' => '1.3.6.1.4.1.9.9.156.1.2.1.1.25',
  'ccmPhoneUnregReason' => '1.3.6.1.4.1.9.9.156.1.2.1.1.26',
  'ccmPhoneRegFailReason' => '1.3.6.1.4.1.9.9.156.1.2.1.1.27',
  'ccmPhoneExtensionTable' => '1.3.6.1.4.1.9.9.156.1.2.2',
  'ccmPhoneExtensionEntry' => '1.3.6.1.4.1.9.9.156.1.2.2.1',
  'ccmPhoneExtensionIndex' => '1.3.6.1.4.1.9.9.156.1.2.2.1.1',
  'ccmPhoneExtension' => '1.3.6.1.4.1.9.9.156.1.2.2.1.2',
  'ccmPhoneExtensionIpAddress' => '1.3.6.1.4.1.9.9.156.1.2.2.1.3',
  'ccmPhoneExtensionMultiLines' => '1.3.6.1.4.1.9.9.156.1.2.2.1.4',
  'ccmPhoneExtensionInetAddressType' => '1.3.6.1.4.1.9.9.156.1.2.2.1.5',
  'ccmPhoneExtensionInetAddress' => '1.3.6.1.4.1.9.9.156.1.2.2.1.6',
  'ccmPhoneFailedTable' => '1.3.6.1.4.1.9.9.156.1.2.3',
  'ccmPhoneFailedEntry' => '1.3.6.1.4.1.9.9.156.1.2.3.1',
  'ccmPhoneFailedIndex' => '1.3.6.1.4.1.9.9.156.1.2.3.1.1',
  'ccmPhoneFailedTime' => '1.3.6.1.4.1.9.9.156.1.2.3.1.2',
  'ccmPhoneFailedName' => '1.3.6.1.4.1.9.9.156.1.2.3.1.3',
  'ccmPhoneFailedInetAddressType' => '1.3.6.1.4.1.9.9.156.1.2.3.1.4',
  'ccmPhoneFailedInetAddress' => '1.3.6.1.4.1.9.9.156.1.2.3.1.5',
  'ccmPhoneFailCauseCode' => '1.3.6.1.4.1.9.9.156.1.2.3.1.6',
  'ccmPhoneFailedMacAddress' => '1.3.6.1.4.1.9.9.156.1.2.3.1.7',
  'ccmPhoneFailedInetAddressIPv4' => '1.3.6.1.4.1.9.9.156.1.2.3.1.8',
  'ccmPhoneFailedInetAddressIPv6' => '1.3.6.1.4.1.9.9.156.1.2.3.1.9',
  'ccmPhoneFailedIPv4Attribute' => '1.3.6.1.4.1.9.9.156.1.2.3.1.10',
  'ccmPhoneFailedIPv6Attribute' => '1.3.6.1.4.1.9.9.156.1.2.3.1.11',
  'ccmPhoneFailedRegFailReason' => '1.3.6.1.4.1.9.9.156.1.2.3.1.12',
  'ccmPhoneStatusUpdateTable' => '1.3.6.1.4.1.9.9.156.1.2.4',
  'ccmPhoneStatusUpdateEntry' => '1.3.6.1.4.1.9.9.156.1.2.4.1',
  'ccmPhoneStatusUpdateIndex' => '1.3.6.1.4.1.9.9.156.1.2.4.1.1',
  'ccmPhoneStatusPhoneIndex' => '1.3.6.1.4.1.9.9.156.1.2.4.1.2',
  'ccmPhoneStatusUpdateTime' => '1.3.6.1.4.1.9.9.156.1.2.4.1.3',
  'ccmPhoneStatusUpdateType' => '1.3.6.1.4.1.9.9.156.1.2.4.1.4',
  'ccmPhoneStatusUpdateReason' => '1.3.6.1.4.1.9.9.156.1.2.4.1.5',
  'ccmPhoneStatusUnregReason' => '1.3.6.1.4.1.9.9.156.1.2.4.1.6',
  'ccmPhoneStatusRegFailReason' => '1.3.6.1.4.1.9.9.156.1.2.4.1.7',
  'ccmPhoneExtnTable' => '1.3.6.1.4.1.9.9.156.1.2.5',
  'ccmPhoneExtnEntry' => '1.3.6.1.4.1.9.9.156.1.2.5.1',
  'ccmPhoneExtnIndex' => '1.3.6.1.4.1.9.9.156.1.2.5.1.1',
  'ccmPhoneExtn' => '1.3.6.1.4.1.9.9.156.1.2.5.1.2',
  'ccmPhoneExtnMultiLines' => '1.3.6.1.4.1.9.9.156.1.2.5.1.3',
  'ccmPhoneExtnInetAddressType' => '1.3.6.1.4.1.9.9.156.1.2.5.1.4',
  'ccmPhoneExtnInetAddress' => '1.3.6.1.4.1.9.9.156.1.2.5.1.5',
  'ccmPhoneExtnStatus' => '1.3.6.1.4.1.9.9.156.1.2.5.1.6',
  'ccmGatewayInfo' => '1.3.6.1.4.1.9.9.156.1.3',
  'ccmGatewayTable' => '1.3.6.1.4.1.9.9.156.1.3.1',
  'ccmGatewayEntry' => '1.3.6.1.4.1.9.9.156.1.3.1.1',
  'ccmGatewayIndex' => '1.3.6.1.4.1.9.9.156.1.3.1.1.1',
  'ccmGatewayName' => '1.3.6.1.4.1.9.9.156.1.3.1.1.2',
  'ccmGatewayType' => '1.3.6.1.4.1.9.9.156.1.3.1.1.3',
  'ccmGatewayDescription' => '1.3.6.1.4.1.9.9.156.1.3.1.1.4',
  'ccmGatewayStatus' => '1.3.6.1.4.1.9.9.156.1.3.1.1.5',
  'ccmGatewayDevicePoolIndex' => '1.3.6.1.4.1.9.9.156.1.3.1.1.6',
  'ccmGatewayInetAddressType' => '1.3.6.1.4.1.9.9.156.1.3.1.1.7',
  'ccmGatewayInetAddress' => '1.3.6.1.4.1.9.9.156.1.3.1.1.8',
  'ccmGatewayProductId' => '1.3.6.1.4.1.9.9.156.1.3.1.1.9',
  'ccmGatewayStatusReason' => '1.3.6.1.4.1.9.9.156.1.3.1.1.10',
  'ccmGatewayTimeLastStatusUpdt' => '1.3.6.1.4.1.9.9.156.1.3.1.1.11',
  'ccmGatewayTimeLastRegistered' => '1.3.6.1.4.1.9.9.156.1.3.1.1.12',
  'ccmGatewayDChannelStatus' => '1.3.6.1.4.1.9.9.156.1.3.1.1.13',
  'ccmGatewayDChannelNumber' => '1.3.6.1.4.1.9.9.156.1.3.1.1.14',
  'ccmGatewayProductTypeIndex' => '1.3.6.1.4.1.9.9.156.1.3.1.1.15',
  'ccmGatewayUnregReason' => '1.3.6.1.4.1.9.9.156.1.3.1.1.16',
  'ccmGatewayRegFailReason' => '1.3.6.1.4.1.9.9.156.1.3.1.1.17',
  'ccmGatewayTrunkInfo' => '1.3.6.1.4.1.9.9.156.1.4',
  'ccmGatewayTrunkTable' => '1.3.6.1.4.1.9.9.156.1.4.1',
  'ccmGatewayTrunkEntry' => '1.3.6.1.4.1.9.9.156.1.4.1.1',
  'ccmGatewayTrunkIndex' => '1.3.6.1.4.1.9.9.156.1.4.1.1.1',
  'ccmGatewayTrunkType' => '1.3.6.1.4.1.9.9.156.1.4.1.1.2',
  'ccmGatewayTrunkName' => '1.3.6.1.4.1.9.9.156.1.4.1.1.3',
  'ccmTrunkGatewayIndex' => '1.3.6.1.4.1.9.9.156.1.4.1.1.4',
  'ccmGatewayTrunkStatus' => '1.3.6.1.4.1.9.9.156.1.4.1.1.5',
  'ccmGlobalInfo' => '1.3.6.1.4.1.9.9.156.1.5',
  'ccmActivePhones' => '1.3.6.1.4.1.9.9.156.1.5.1',
  'ccmInActivePhones' => '1.3.6.1.4.1.9.9.156.1.5.2',
  'ccmActiveGateways' => '1.3.6.1.4.1.9.9.156.1.5.3',
  'ccmInActiveGateways' => '1.3.6.1.4.1.9.9.156.1.5.4',
  'ccmRegisteredPhones' => '1.3.6.1.4.1.9.9.156.1.5.5',
  'ccmUnregisteredPhones' => '1.3.6.1.4.1.9.9.156.1.5.6',
  'ccmRejectedPhones' => '1.3.6.1.4.1.9.9.156.1.5.7',
  'ccmRegisteredGateways' => '1.3.6.1.4.1.9.9.156.1.5.8',
  'ccmUnregisteredGateways' => '1.3.6.1.4.1.9.9.156.1.5.9',
  'ccmRejectedGateways' => '1.3.6.1.4.1.9.9.156.1.5.10',
  'ccmRegisteredMediaDevices' => '1.3.6.1.4.1.9.9.156.1.5.11',
  'ccmUnregisteredMediaDevices' => '1.3.6.1.4.1.9.9.156.1.5.12',
  'ccmRejectedMediaDevices' => '1.3.6.1.4.1.9.9.156.1.5.13',
  'ccmRegisteredCTIDevices' => '1.3.6.1.4.1.9.9.156.1.5.14',
  'ccmUnregisteredCTIDevices' => '1.3.6.1.4.1.9.9.156.1.5.15',
  'ccmRejectedCTIDevices' => '1.3.6.1.4.1.9.9.156.1.5.16',
  'ccmRegisteredVoiceMailDevices' => '1.3.6.1.4.1.9.9.156.1.5.17',
  'ccmUnregisteredVoiceMailDevices' => '1.3.6.1.4.1.9.9.156.1.5.18',
  'ccmRejectedVoiceMailDevices' => '1.3.6.1.4.1.9.9.156.1.5.19',
  'ccmCallManagerStartTime' => '1.3.6.1.4.1.9.9.156.1.5.20',
  'ccmPhoneTableStateId' => '1.3.6.1.4.1.9.9.156.1.5.21',
  'ccmPhoneExtensionTableStateId' => '1.3.6.1.4.1.9.9.156.1.5.22',
  'ccmPhoneStatusUpdateTableStateId' => '1.3.6.1.4.1.9.9.156.1.5.23',
  'ccmGatewayTableStateId' => '1.3.6.1.4.1.9.9.156.1.5.24',
  'ccmCTIDeviceTableStateId' => '1.3.6.1.4.1.9.9.156.1.5.25',
  'ccmCTIDeviceDirNumTableStateId' => '1.3.6.1.4.1.9.9.156.1.5.26',
  'ccmPhStatUpdtTblLastAddedIndex' => '1.3.6.1.4.1.9.9.156.1.5.27',
  'ccmPhFailedTblLastAddedIndex' => '1.3.6.1.4.1.9.9.156.1.5.28',
  'ccmSystemVersion' => '1.3.6.1.4.1.9.9.156.1.5.29',
  'ccmInstallationId' => '1.3.6.1.4.1.9.9.156.1.5.30',
  'ccmPartiallyRegisteredPhones' => '1.3.6.1.4.1.9.9.156.1.5.31',
  'ccmH323TableEntries' => '1.3.6.1.4.1.9.9.156.1.5.32',
  'ccmSIPTableEntries' => '1.3.6.1.4.1.9.9.156.1.5.33',
  'ccmMediaDeviceInfo' => '1.3.6.1.4.1.9.9.156.1.6',
  'ccmMediaDeviceTable' => '1.3.6.1.4.1.9.9.156.1.6.1',
  'ccmMediaDeviceEntry' => '1.3.6.1.4.1.9.9.156.1.6.1.1',
  'ccmMediaDeviceIndex' => '1.3.6.1.4.1.9.9.156.1.6.1.1.1',
  'ccmMediaDeviceName' => '1.3.6.1.4.1.9.9.156.1.6.1.1.2',
  'ccmMediaDeviceType' => '1.3.6.1.4.1.9.9.156.1.6.1.1.3',
  'ccmMediaDeviceDescription' => '1.3.6.1.4.1.9.9.156.1.6.1.1.4',
  'ccmMediaDeviceStatus' => '1.3.6.1.4.1.9.9.156.1.6.1.1.5',
  'ccmMediaDeviceDevicePoolIndex' => '1.3.6.1.4.1.9.9.156.1.6.1.1.6',
  'ccmMediaDeviceInetAddressType' => '1.3.6.1.4.1.9.9.156.1.6.1.1.7',
  'ccmMediaDeviceInetAddress' => '1.3.6.1.4.1.9.9.156.1.6.1.1.8',
  'ccmMediaDeviceStatusReason' => '1.3.6.1.4.1.9.9.156.1.6.1.1.9',
  'ccmMediaDeviceTimeLastStatusUpdt' => '1.3.6.1.4.1.9.9.156.1.6.1.1.10',
  'ccmMediaDeviceTimeLastRegistered' => '1.3.6.1.4.1.9.9.156.1.6.1.1.11',
  'ccmMediaDeviceProductTypeIndex' => '1.3.6.1.4.1.9.9.156.1.6.1.1.12',
  'ccmMediaDeviceInetAddressIPv4' => '1.3.6.1.4.1.9.9.156.1.6.1.1.13',
  'ccmMediaDeviceInetAddressIPv6' => '1.3.6.1.4.1.9.9.156.1.6.1.1.14',
  'ccmMediaDeviceUnregReason' => '1.3.6.1.4.1.9.9.156.1.6.1.1.15',
  'ccmMediaDeviceRegFailReason' => '1.3.6.1.4.1.9.9.156.1.6.1.1.16',
  'ccmGatekeeperInfo' => '1.3.6.1.4.1.9.9.156.1.7',
  'ccmGatekeeperTable' => '1.3.6.1.4.1.9.9.156.1.7.1',
  'ccmGatekeeperEntry' => '1.3.6.1.4.1.9.9.156.1.7.1.1',
  'ccmGatekeeperIndex' => '1.3.6.1.4.1.9.9.156.1.7.1.1.1',
  'ccmGatekeeperName' => '1.3.6.1.4.1.9.9.156.1.7.1.1.2',
  'ccmGatekeeperType' => '1.3.6.1.4.1.9.9.156.1.7.1.1.3',
  'ccmGatekeeperDescription' => '1.3.6.1.4.1.9.9.156.1.7.1.1.4',
  'ccmGatekeeperStatus' => '1.3.6.1.4.1.9.9.156.1.7.1.1.5',
  'ccmGatekeeperDevicePoolIndex' => '1.3.6.1.4.1.9.9.156.1.7.1.1.6',
  'ccmGatekeeperInetAddressType' => '1.3.6.1.4.1.9.9.156.1.7.1.1.7',
  'ccmGatekeeperInetAddress' => '1.3.6.1.4.1.9.9.156.1.7.1.1.8',
  'ccmCTIDeviceInfo' => '1.3.6.1.4.1.9.9.156.1.8',
  'ccmCTIDeviceTable' => '1.3.6.1.4.1.9.9.156.1.8.1',
  'ccmCTIDeviceEntry' => '1.3.6.1.4.1.9.9.156.1.8.1.1',
  'ccmCTIDeviceIndex' => '1.3.6.1.4.1.9.9.156.1.8.1.1.1',
  'ccmCTIDeviceName' => '1.3.6.1.4.1.9.9.156.1.8.1.1.2',
  'ccmCTIDeviceType' => '1.3.6.1.4.1.9.9.156.1.8.1.1.3',
  'ccmCTIDeviceDescription' => '1.3.6.1.4.1.9.9.156.1.8.1.1.4',
  'ccmCTIDeviceStatus' => '1.3.6.1.4.1.9.9.156.1.8.1.1.5',
  'ccmCTIDevicePoolIndex' => '1.3.6.1.4.1.9.9.156.1.8.1.1.6',
  'ccmCTIDeviceInetAddressType' => '1.3.6.1.4.1.9.9.156.1.8.1.1.7',
  'ccmCTIDeviceInetAddress' => '1.3.6.1.4.1.9.9.156.1.8.1.1.8',
  'ccmCTIDeviceAppInfo' => '1.3.6.1.4.1.9.9.156.1.8.1.1.9',
  'ccmCTIDeviceStatusReason' => '1.3.6.1.4.1.9.9.156.1.8.1.1.10',
  'ccmCTIDeviceTimeLastStatusUpdt' => '1.3.6.1.4.1.9.9.156.1.8.1.1.11',
  'ccmCTIDeviceTimeLastRegistered' => '1.3.6.1.4.1.9.9.156.1.8.1.1.12',
  'ccmCTIDeviceProductTypeIndex' => '1.3.6.1.4.1.9.9.156.1.8.1.1.13',
  'ccmCTIDeviceInetAddressIPv4' => '1.3.6.1.4.1.9.9.156.1.8.1.1.14',
  'ccmCTIDeviceInetAddressIPv6' => '1.3.6.1.4.1.9.9.156.1.8.1.1.15',
  'ccmCTIDeviceUnregReason' => '1.3.6.1.4.1.9.9.156.1.8.1.1.16',
  'ccmCTIDeviceRegFailReason' => '1.3.6.1.4.1.9.9.156.1.8.1.1.17',
  'ccmCTIDeviceDirNumTable' => '1.3.6.1.4.1.9.9.156.1.8.2',
  'ccmCTIDeviceDirNumEntry' => '1.3.6.1.4.1.9.9.156.1.8.2.1',
  'ccmCTIDeviceDirNumIndex' => '1.3.6.1.4.1.9.9.156.1.8.2.1.1',
  'ccmCTIDeviceDirNum' => '1.3.6.1.4.1.9.9.156.1.8.2.1.2',
  'ccmAlarmConfigInfo' => '1.3.6.1.4.1.9.9.156.1.9',
  'ccmCallManagerAlarmEnable' => '1.3.6.1.4.1.9.9.156.1.9.1',
  'ccmPhoneFailedAlarmInterval' => '1.3.6.1.4.1.9.9.156.1.9.2',
  'ccmPhoneFailedStorePeriod' => '1.3.6.1.4.1.9.9.156.1.9.3',
  'ccmPhoneStatusUpdateAlarmInterv' => '1.3.6.1.4.1.9.9.156.1.9.4',
  'ccmPhoneStatusUpdateStorePeriod' => '1.3.6.1.4.1.9.9.156.1.9.5',
  'ccmGatewayAlarmEnable' => '1.3.6.1.4.1.9.9.156.1.9.6',
  'ccmMaliciousCallAlarmEnable' => '1.3.6.1.4.1.9.9.156.1.9.7',
  'ccmNotificationsInfo' => '1.3.6.1.4.1.9.9.156.1.10',
  'ccmAlarmSeverity' => '1.3.6.1.4.1.9.9.156.1.10.1',
  'ccmFailCauseCode' => '1.3.6.1.4.1.9.9.156.1.10.2',
  'ccmPhoneFailures' => '1.3.6.1.4.1.9.9.156.1.10.3',
  'ccmPhoneUpdates' => '1.3.6.1.4.1.9.9.156.1.10.4',
  'ccmGatewayFailCauseCode' => '1.3.6.1.4.1.9.9.156.1.10.5',
  'ccmMediaResourceType' => '1.3.6.1.4.1.9.9.156.1.10.6',
  'ccmMediaResourceListName' => '1.3.6.1.4.1.9.9.156.1.10.7',
  'ccmRouteListName' => '1.3.6.1.4.1.9.9.156.1.10.8',
  'ccmGatewayPhysIfIndex' => '1.3.6.1.4.1.9.9.156.1.10.9',
  'ccmGatewayPhysIfL2Status' => '1.3.6.1.4.1.9.9.156.1.10.10',
  'ccmMaliCallCalledPartyName' => '1.3.6.1.4.1.9.9.156.1.10.11',
  'ccmMaliCallCalledPartyNumber' => '1.3.6.1.4.1.9.9.156.1.10.12',
  'ccmMaliCallCalledDeviceName' => '1.3.6.1.4.1.9.9.156.1.10.13',
  'ccmMaliCallCallingPartyName' => '1.3.6.1.4.1.9.9.156.1.10.14',
  'ccmMaliCallCallingPartyNumber' => '1.3.6.1.4.1.9.9.156.1.10.15',
  'ccmMaliCallCallingDeviceName' => '1.3.6.1.4.1.9.9.156.1.10.16',
  'ccmMaliCallTime' => '1.3.6.1.4.1.9.9.156.1.10.17',
  'ccmQualityRprtSourceDevName' => '1.3.6.1.4.1.9.9.156.1.10.18',
  'ccmQualityRprtClusterId' => '1.3.6.1.4.1.9.9.156.1.10.19',
  'ccmQualityRprtCategory' => '1.3.6.1.4.1.9.9.156.1.10.20',
  'ccmQualityRprtReasonCode' => '1.3.6.1.4.1.9.9.156.1.10.21',
  'ccmQualityRprtTime' => '1.3.6.1.4.1.9.9.156.1.10.22',
  'ccmTLSDevName' => '1.3.6.1.4.1.9.9.156.1.10.23',
  'ccmTLSDevInetAddressType' => '1.3.6.1.4.1.9.9.156.1.10.24',
  'ccmTLSDevInetAddress' => '1.3.6.1.4.1.9.9.156.1.10.25',
  'ccmTLSConnFailTime' => '1.3.6.1.4.1.9.9.156.1.10.26',
  'ccmTLSConnectionFailReasonCode' => '1.3.6.1.4.1.9.9.156.1.10.27',
  'ccmGatewayRegFailCauseCode' => '1.3.6.1.4.1.9.9.156.1.10.28',
  'ccmH323DeviceInfo' => '1.3.6.1.4.1.9.9.156.1.11',
  'ccmH323DeviceTable' => '1.3.6.1.4.1.9.9.156.1.11.1',
  'ccmH323DeviceEntry' => '1.3.6.1.4.1.9.9.156.1.11.1.1',
  'ccmH323DevIndex' => '1.3.6.1.4.1.9.9.156.1.11.1.1.1',
  'ccmH323DevName' => '1.3.6.1.4.1.9.9.156.1.11.1.1.2',
  'ccmH323DevProductId' => '1.3.6.1.4.1.9.9.156.1.11.1.1.3',
  'ccmH323DevDescription' => '1.3.6.1.4.1.9.9.156.1.11.1.1.4',
  'ccmH323DevInetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.5',
  'ccmH323DevInetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.6',
  'ccmH323DevCnfgGKInetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.7',
  'ccmH323DevCnfgGKInetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.8',
  'ccmH323DevAltGK1InetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.9',
  'ccmH323DevAltGK1InetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.10',
  'ccmH323DevAltGK2InetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.11',
  'ccmH323DevAltGK2InetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.12',
  'ccmH323DevAltGK3InetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.13',
  'ccmH323DevAltGK3InetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.14',
  'ccmH323DevAltGK4InetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.15',
  'ccmH323DevAltGK4InetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.16',
  'ccmH323DevAltGK5InetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.17',
  'ccmH323DevAltGK5InetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.18',
  'ccmH323DevActGKInetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.19',
  'ccmH323DevActGKInetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.20',
  'ccmH323DevStatus' => '1.3.6.1.4.1.9.9.156.1.11.1.1.21',
  'ccmH323DevStatusReason' => '1.3.6.1.4.1.9.9.156.1.11.1.1.22',
  'ccmH323DevTimeLastStatusUpdt' => '1.3.6.1.4.1.9.9.156.1.11.1.1.23',
  'ccmH323DevTimeLastRegistered' => '1.3.6.1.4.1.9.9.156.1.11.1.1.24',
  'ccmH323DevRmtCM1InetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.25',
  'ccmH323DevRmtCM1InetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.26',
  'ccmH323DevRmtCM2InetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.27',
  'ccmH323DevRmtCM2InetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.28',
  'ccmH323DevRmtCM3InetAddressType' => '1.3.6.1.4.1.9.9.156.1.11.1.1.29',
  'ccmH323DevRmtCM3InetAddress' => '1.3.6.1.4.1.9.9.156.1.11.1.1.30',
  'ccmH323DevProductTypeIndex' => '1.3.6.1.4.1.9.9.156.1.11.1.1.31',
  'ccmH323DevUnregReason' => '1.3.6.1.4.1.9.9.156.1.11.1.1.32',
  'ccmH323DevRegFailReason' => '1.3.6.1.4.1.9.9.156.1.11.1.1.33',
  'ccmVoiceMailDeviceInfo' => '1.3.6.1.4.1.9.9.156.1.12',
  'ccmVoiceMailDeviceTable' => '1.3.6.1.4.1.9.9.156.1.12.1',
  'ccmVoiceMailDeviceEntry' => '1.3.6.1.4.1.9.9.156.1.12.1.1',
  'ccmVMailDevIndex' => '1.3.6.1.4.1.9.9.156.1.12.1.1.1',
  'ccmVMailDevName' => '1.3.6.1.4.1.9.9.156.1.12.1.1.2',
  'ccmVMailDevProductId' => '1.3.6.1.4.1.9.9.156.1.12.1.1.3',
  'ccmVMailDevDescription' => '1.3.6.1.4.1.9.9.156.1.12.1.1.4',
  'ccmVMailDevStatus' => '1.3.6.1.4.1.9.9.156.1.12.1.1.5',
  'ccmVMailDevInetAddressType' => '1.3.6.1.4.1.9.9.156.1.12.1.1.6',
  'ccmVMailDevInetAddress' => '1.3.6.1.4.1.9.9.156.1.12.1.1.7',
  'ccmVMailDevStatusReason' => '1.3.6.1.4.1.9.9.156.1.12.1.1.8',
  'ccmVMailDevTimeLastStatusUpdt' => '1.3.6.1.4.1.9.9.156.1.12.1.1.9',
  'ccmVMailDevTimeLastRegistered' => '1.3.6.1.4.1.9.9.156.1.12.1.1.10',
  'ccmVMailDevProductTypeIndex' => '1.3.6.1.4.1.9.9.156.1.12.1.1.11',
  'ccmVMailDevUnregReason' => '1.3.6.1.4.1.9.9.156.1.12.1.1.12',
  'ccmVMailDevRegFailReason' => '1.3.6.1.4.1.9.9.156.1.12.1.1.13',
  'ccmVoiceMailDeviceDirNumTable' => '1.3.6.1.4.1.9.9.156.1.12.2',
  'ccmVoiceMailDeviceDirNumEntry' => '1.3.6.1.4.1.9.9.156.1.12.2.1',
  'ccmVMailDevDirNumIndex' => '1.3.6.1.4.1.9.9.156.1.12.2.1.1',
  'ccmVMailDevDirNum' => '1.3.6.1.4.1.9.9.156.1.12.2.1.2',
  'ccmQualityReportAlarmConfigInfo' => '1.3.6.1.4.1.9.9.156.1.13',
  'ccmQualityReportAlarmEnable' => '1.3.6.1.4.1.9.9.156.1.13.1',
  'ccmSIPDeviceInfo' => '1.3.6.1.4.1.9.9.156.1.14',
  'ccmSIPDeviceTable' => '1.3.6.1.4.1.9.9.156.1.14.1',
  'ccmSIPDeviceEntry' => '1.3.6.1.4.1.9.9.156.1.14.1.1',
  'ccmSIPDevIndex' => '1.3.6.1.4.1.9.9.156.1.14.1.1.1',
  'ccmSIPDevName' => '1.3.6.1.4.1.9.9.156.1.14.1.1.2',
  'ccmSIPDevProductTypeIndex' => '1.3.6.1.4.1.9.9.156.1.14.1.1.3',
  'ccmSIPDevDescription' => '1.3.6.1.4.1.9.9.156.1.14.1.1.4',
  'ccmSIPDevInetAddressType' => '1.3.6.1.4.1.9.9.156.1.14.1.1.5',
  'ccmSIPDevInetAddress' => '1.3.6.1.4.1.9.9.156.1.14.1.1.6',
  'ccmSIPInTransportProtocolType' => '1.3.6.1.4.1.9.9.156.1.14.1.1.7',
  'ccmSIPInPortNumber' => '1.3.6.1.4.1.9.9.156.1.14.1.1.8',
  'ccmSIPOutTransportProtocolType' => '1.3.6.1.4.1.9.9.156.1.14.1.1.9',
  'ccmSIPOutPortNumber' => '1.3.6.1.4.1.9.9.156.1.14.1.1.10',
  'ccmSIPDevInetAddressIPv4' => '1.3.6.1.4.1.9.9.156.1.14.1.1.11',
  'ccmSIPDevInetAddressIPv6' => '1.3.6.1.4.1.9.9.156.1.14.1.1.12',
  'ccmMIBNotificationPrefix' => '1.3.6.1.4.1.9.9.156.2',
  'ccmMIBNotifications' => '1.3.6.1.4.1.9.9.156.2',
  'ciscoCcmMIBConformance' => '1.3.6.1.4.1.9.9.156.3',
  'ciscoCcmMIBCompliances' => '1.3.6.1.4.1.9.9.156.3.1',
  'ciscoCcmMIBCompliance' => '1.3.6.1.4.1.9.9.156.3.1.1',
  'ciscoCcmMIBComplianceRev1' => '1.3.6.1.4.1.9.9.156.3.1.2',
  'ciscoCcmMIBComplianceRev2' => '1.3.6.1.4.1.9.9.156.3.1.3',
  'ciscoCcmMIBComplianceRev3' => '1.3.6.1.4.1.9.9.156.3.1.4',
  'ciscoCcmMIBComplianceRev4' => '1.3.6.1.4.1.9.9.156.3.1.5',
  'ciscoCcmMIBComplianceRev5' => '1.3.6.1.4.1.9.9.156.3.1.6',
  'ciscoCcmMIBComplianceRev6' => '1.3.6.1.4.1.9.9.156.3.1.7',
  'ciscoCcmMIBComplianceRev7' => '1.3.6.1.4.1.9.9.156.3.1.8',
  'ciscoCcmMIBGroups' => '1.3.6.1.4.1.9.9.156.3.2',
  'ccmInfoGroup' => '1.3.6.1.4.1.9.9.156.3.2.1',
  'ccmPhoneInfoGroup' => '1.3.6.1.4.1.9.9.156.3.2.2',
  'ccmGatewayInfoGroup' => '1.3.6.1.4.1.9.9.156.3.2.3',
  'ccmInfoGroupRev1' => '1.3.6.1.4.1.9.9.156.3.2.4',
  'ccmPhoneInfoGroupRev1' => '1.3.6.1.4.1.9.9.156.3.2.5',
  'ccmGatewayInfoGroupRev1' => '1.3.6.1.4.1.9.9.156.3.2.6',
  'ccmMediaDeviceInfoGroup' => '1.3.6.1.4.1.9.9.156.3.2.7',
  'ccmGatekeeperInfoGroup' => '1.3.6.1.4.1.9.9.156.3.2.8',
  'ccmCTIDeviceInfoGroup' => '1.3.6.1.4.1.9.9.156.3.2.9',
  'ccmNotificationsInfoGroup' => '1.3.6.1.4.1.9.9.156.3.2.10',
  'ccmNotificationsGroup' => '1.3.6.1.4.1.9.9.156.3.2.11',
  'ccmInfoGroupRev2' => '1.3.6.1.4.1.9.9.156.3.2.12',
  'ccmPhoneInfoGroupRev2' => '1.3.6.1.4.1.9.9.156.3.2.13',
  'ccmGatewayInfoGroupRev2' => '1.3.6.1.4.1.9.9.156.3.2.14',
  'ccmMediaDeviceInfoGroupRev1' => '1.3.6.1.4.1.9.9.156.3.2.15',
  'ccmCTIDeviceInfoGroupRev1' => '1.3.6.1.4.1.9.9.156.3.2.16',
  'ccmH323DeviceInfoGroup' => '1.3.6.1.4.1.9.9.156.3.2.17',
  'ccmVoiceMailDeviceInfoGroup' => '1.3.6.1.4.1.9.9.156.3.2.18',
  'ccmNotificationsInfoGroupRev1' => '1.3.6.1.4.1.9.9.156.3.2.19',
  'ccmInfoGroupRev3' => '1.3.6.1.4.1.9.9.156.3.2.20',
  'ccmNotificationsInfoGroupRev2' => '1.3.6.1.4.1.9.9.156.3.2.21',
  'ccmNotificationsGroupRev1' => '1.3.6.1.4.1.9.9.156.3.2.22',
  'ccmSIPDeviceInfoGroup' => '1.3.6.1.4.1.9.9.156.3.2.23',
  'ccmPhoneInfoGroupRev3' => '1.3.6.1.4.1.9.9.156.3.2.24',
  'ccmGatewayInfoGroupRev3' => '1.3.6.1.4.1.9.9.156.3.2.25',
  'ccmMediaDeviceInfoGroupRev2' => '1.3.6.1.4.1.9.9.156.3.2.26',
  'ccmCTIDeviceInfoGroupRev2' => '1.3.6.1.4.1.9.9.156.3.2.27',
  'ccmH323DeviceInfoGroupRev1' => '1.3.6.1.4.1.9.9.156.3.2.28',
  'ccmVoiceMailDeviceInfoGroupRev1' => '1.3.6.1.4.1.9.9.156.3.2.29',
  'ccmPhoneInfoGroupRev4' => '1.3.6.1.4.1.9.9.156.3.2.30',
  'ccmSIPDeviceInfoGroupRev1' => '1.3.6.1.4.1.9.9.156.3.2.31',
  'ccmNotificationsInfoGroupRev3' => '1.3.6.1.4.1.9.9.156.3.2.32',
  'ccmNotificationsGroupRev2' => '1.3.6.1.4.1.9.9.156.3.2.33',
  'ccmInfoGroupRev4' => '1.3.6.1.4.1.9.9.156.3.2.34',
  'ccmPhoneInfoGroupRev5' => '1.3.6.1.4.1.9.9.156.3.2.35',
  'ccmMediaDeviceInfoGroupRev3' => '1.3.6.1.4.1.9.9.156.3.2.36',
  'ccmSIPDeviceInfoGroupRev2' => '1.3.6.1.4.1.9.9.156.3.2.37',
  'ccmNotificationsInfoGroupRev4' => '1.3.6.1.4.1.9.9.156.3.2.38',
  'ccmH323DeviceInfoGroupRev2' => '1.3.6.1.4.1.9.9.156.3.2.39',
  'ccmCTIDeviceInfoGroupRev3' => '1.3.6.1.4.1.9.9.156.3.2.40',
  'ccmPhoneInfoGroupRev6' => '1.3.6.1.4.1.9.9.156.3.2.41',
  'ccmNotificationsInfoGroupRev5' => '1.3.6.1.4.1.9.9.156.3.2.42',
  'ccmGatewayInfoGroupRev4' => '1.3.6.1.4.1.9.9.156.3.2.43',
  'ccmMediaDeviceInfoGroupRev4' => '1.3.6.1.4.1.9.9.156.3.2.44',
  'ccmCTIDeviceInfoGroupRev4' => '1.3.6.1.4.1.9.9.156.3.2.45',
  'ccmH323DeviceInfoGroupRev3' => '1.3.6.1.4.1.9.9.156.3.2.46',
  'ccmVoiceMailDeviceInfoGroupRev2' => '1.3.6.1.4.1.9.9.156.3.2.47',
  'ccmNotificationsGroupRev3' => '1.3.6.1.4.1.9.9.156.3.2.48',
};


1;

__END__
