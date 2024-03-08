package Monitoring::GLPlugin::SNMP::MibsAndOids::HUAWEIWLANSTATIONMIB;

$Monitoring::GLPlugin::SNMP::MibsAndOids::origin->{'HUAWEI-WLAN-STATION-MIB'} = {
  url => '',
  name => 'HUAWEI-WLAN-STATION-MIB',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::mib_ids->{'HUAWEI-WLAN-STATION-MIB'} =
    '1.3.6.1.4.1.2011.6.139.18';

$Monitoring::GLPlugin::SNMP::MibsAndOids::mibs_and_oids->{'HUAWEI-WLAN-STATION-MIB'} = {
  'hwWlanStation' => '1.3.6.1.4.1.2011.6.139.18',
  'hwWlanStationObjects' => '1.3.6.1.4.1.2011.6.139.18.1',
  'hwWlanStaTraps' => '1.3.6.1.4.1.2011.6.139.18.1.1',
  'hwWlanStaTrap' => '1.3.6.1.4.1.2011.6.139.18.1.1.1',
  'hwWlanStaTrapObjects' => '1.3.6.1.4.1.2011.6.139.18.1.1.2',
  'hwWlanStaAuthenticationMode' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.1',
  'hwWlanStaAuthenticationFailCause' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.2',
  'hwWlanStaAssociationFailCause' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.3',
  'hwWlanStaAssocBssid' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.4',
  'hwWlanStaFailCodeType' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.5',
  'hwWlanStaFailCodeTypeDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaFailCodeType',
  'hwWlanWepIDConflictTrapAPMAC' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.6',
  'hwWlanWepIDConflictTrapAPName' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.7',
  'hwWlanWepIDConflictTrapRadioId' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.8',
  'hwWlanWepIDConflictTrapPreSSID' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.9',
  'hwWlanWepIDConflictTrapCurrSSID' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.10',
  'hwWlanWepIDConflictTrapCipherIdx' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.11',
  'hwWlanWlanStaAuthEncryptMode' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.12',
  'hwWlanWlanVapAuthEncryptMode' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.13',
  'hwWlanStaAuthenticationFailCauseStr' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.14',
  'hwWlanStaAssociationFailCauseStr' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.15',
  'hwWlanSignalStrengthThreshold' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.16',
  'hwWlanStaTrapOccurTime' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.17',
  'hwWlanConflictIPAddress' => '1.3.6.1.4.1.2011.6.139.18.1.1.2.18',
  'hwWlanStationTable' => '1.3.6.1.4.1.2011.6.139.18.1.2',
  'hwWlanStationEntry' => '1.3.6.1.4.1.2011.6.139.18.1.2.1',
  'hwWlanStaMac' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.1',
  'hwWlanStaUsername' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.2',
  'hwWlanStaApMac' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.3',
  'hwWlanStaApName' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.4',
  'hwWlanStaApGroup' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.5',
  'hwWlanStaRadioId' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.6',
  'hwWlanStaAssocBand' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.7',
  'hwWlanStaSupportBand' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.8',
  'hwWlanStaAccessChannel' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.9',
  'hwWlanStaRfMode' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.10',
  'hwWlanStaRfModeDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaRfMode',
  'hwWlanStaHtMode' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.11',
  'hwWlanStaHtModeDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaHtMode',
  'hwWlanStaMcsVal' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.12',
  'hwWlanStaShortGIStatus' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.13',
  'hwWlanStaShortGIStatusDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaShortGIStatus',
  'hwWlanStaConnectRxRate' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.14',
  'hwWlanStaConnectTxRate' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.15',
  'hwWlanStaEssName' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.16',
  'hwWlanStaBSSID' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.17',
  'hwWlanStaSsid' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.18',
  'hwWlanStaStatus' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.19',
  'hwWlanStaStatusDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaStatus',
  'hwWlanStaAuthenMethod' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.20',
  'hwWlanStaAuthenMethodDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaAuthenMethod',
  'hwWlanStaEncryptMethod' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.21',
  'hwWlanStaEncryptMethodDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaEncryptMethod',
  'hwWlanStaQosMode' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.22',
  'hwWlanStaQosModeDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaQosMode',
  'hwWlanStaRoamStatus' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.23',
  'hwWlanStaRoamStatusDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaRoamStatus',
  'hwWlanStaVlan' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.24',
  'hwWlanStaIP' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.25',
  'hwWlanStaIPv6' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.26',
  'hwWlanStaGateway' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.27',
  'hwWlanStaAssocTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.28',
  'hwWlanStaAccessTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.29',
  'hwWlanStaOnlineTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.30',
  'hwWlanStaAccessOnlineTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.31',
  'hwWlanStaStatOperMode' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.32',
  'hwWlanStaStatOperModeDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaStatOperMode',
  'hwWlanStaWirelessStatRxFrames' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.33',
  'hwWlanStaWirelessRxBytes' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.34',
  'hwWlanStaWirelessRxRate' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.35',
  'hwWlanStaWirelessStatTxFrames' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.36',
  'hwWlanStaWirelessTxBytes' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.37',
  'hwWlanStaWirelessTxRate' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.38',
  'hwWlanStaPeriodSendDropFrames' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.39',
  'hwWlanStaPeriodReSendFrames' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.40',
  'hwWlanStaPeriodReSendBytes' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.41',
  'hwWlanStaRssi' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.42',
  'hwWlanStaNoise' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.43',
  'hwWlanStaSnrUs' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.44',
  'hwWlanStaRxPowerUs' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.45',
  'hwWlanStaChannelUtilRate' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.46',
  'hwWlanStaChannelBusyRate' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.47',
  'hwWlanStaChannelTxRatio' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.48',
  'hwWlanStaChannelRxRatio' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.49',
  'hwWlanStaChannelFreeRate' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.50',
  'hwWlanStaChannelInterfRate' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.51',
  'hwWlanStaPeriodSendFrames' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.52',
  'hwWlanStaApId' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.53',
  'hwWlanStationUapsdCapacity' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.54',
  'hwWlanStationPowerSavePercent' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.55',
  'hwWlanStaAssocStartTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.56',
  'hwWlanStaAssocSuccessTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.57',
  'hwWlanStaAuthStartTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.58',
  'hwWlanStaAuthSuccessTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.59',
  'hwWlanStaDhcpStartTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.60',
  'hwWlanStaDhcpSuccessTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.61',
  'hwWlanStaVHTCapable' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.62',
  'hwWlanStaVHTCapableDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaVHTCapable',
  'hwWlanStaVHTTxBFCapable' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.63',
  'hwWlanStaVHTTxBFCapableDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaVHTTxBFCapable',
  'hwWlanStaMUMIMOCapable' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.64',
  'hwWlanStaMUMIMOCapableDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaMUMIMOCapable',
  'hwWlanStaWpaStartTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.65',
  'hwWlanStaWpaSuccessTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.66',
  'hwWlanStaWirelessPacketDelay' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.67',
  'hwWlanStaAccessSuccessRate' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.68',
  'hwWlanStaTotalAccessTime' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.69',
  'hwWlanStaDelayStatus' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.70',
  'hwWlanStaDelayStatusDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaDelayStatus',
  'hwWlanStaAssocDuration' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.71',
  'hwWlanStaWpaDuration' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.72',
  'hwWlanStaAuthDuration' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.73',
  'hwWlanStaDhcpDuration' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.74',
  'hwWlanStationDevType' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.75',
  'hwWlanStaNaviACID' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.76',
  'hwWlanStaWirelessStatRxIPv6Frames' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.77',
  'hwWlanStaWirelessRxIPv6Bytes' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.78',
  'hwWlanStaWirelessStatTxIPv6Frames' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.79',
  'hwWlanStaWirelessTxIPv6Bytes' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.80',
  'hwWlanStaGatewayIPv6' => '1.3.6.1.4.1.2011.6.139.18.1.2.1.81',
  'hwWlanStationApStatTable' => '1.3.6.1.4.1.2011.6.139.18.1.3',
  'hwWlanStationApStatEntry' => '1.3.6.1.4.1.2011.6.139.18.1.3.1',
  'hwWlanApAssocStatApMac' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.1',
  'hwWlanTotalOnlineTime' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.2',
  'hwWlanTotalAssociatedStationCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.3',
  'hwWlanCurrAssociatedStationCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.4',
  'hwWlanAssociationRequestCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.5',
  'hwWlanAssociationRejectCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.6',
  'hwWlanAssociationFailedCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.7',
  'hwWlanReAssociationRequestCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.8',
  'hwWlanReAssociationRejectCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.9',
  'hwWlanReAssociationFailedCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.10',
  'hwWlanDisAssocOfUserNotifiedCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.11',
  'hwWlanDisAssocOfStaRoamCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.12',
  'hwWlanDisAssocOfStaAgeCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.13',
  'hwWlanDisAssocOfApUnableHandleCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.14',
  'hwWlanDisAssocOfOtherReasonsCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.15',
  'hwWlanAssocRequestCntByResource' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.16',
  'hwWlanStaExceptionalOfflineCnt' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.17',
  'hwWlanReAssociationSuccessCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.18',
  'hwWlanBSSNotSupportAssocFailCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.19',
  'hwWlanStaAccessRequestCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.20',
  'hwWlanStaAccessRequestFailedCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.21',
  'hwWlanStaAuthenRequestCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.22',
  'hwWlanStaAuthenRequestFailedCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.23',
  'hwWlanRefusedStaNumByResource' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.24',
  'hwWlanStaAssocAndReAssocRequestCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.25',
  'hwWlanStaAuthenRequestSuccessCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.26',
  'hwWlanStationApStatApId' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.27',
  'hwWlanStaGetIPFailedCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.28',
  'hwWlanStaGetIPSuccessCount' => '1.3.6.1.4.1.2011.6.139.18.1.3.1.29',
  'hwWlanStaOnlineFailInfo' => '1.3.6.1.4.1.2011.6.139.18.1.4',
  'hwWlanStaOnlineFailTable' => '1.3.6.1.4.1.2011.6.139.18.1.4.1',
  'hwWlanStaOnlineFailEntry' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1',
  'hwWlanStaOnlineFailMacAddress' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.1',
  'hwWlanStaOnlineFailReasonIndex' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.2',
  'hwWlanStaOnlineFailApMac' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.3',
  'hwWlanStaOnlineFailApName' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.4',
  'hwWlanStaOnlineFailRadioId' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.5',
  'hwWlanStaOnlineFailWlanId' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.6',
  'hwWlanStaOnlineFailLastFailTime' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.7',
  'hwWlanStaOnlineFailReason' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.8',
  'hwWlanStaOnlineFailSsid' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.9',
  'hwWlanStaOnlineFailRowStatus' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.10',
  'hwWlanStaOnlineFailApId' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.11',
  'hwWlanStaOnlineFailDevType' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.12',
  'hwWlanStaOnlineFailAcId' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.13',
  'hwWlanStaOnlineFailAcName' => '1.3.6.1.4.1.2011.6.139.18.1.4.1.1.14',
  'hwWlanStaOnlineFailReasonTable' => '1.3.6.1.4.1.2011.6.139.18.1.4.2',
  'hwWlanStaOnlineFailReasonEntry' => '1.3.6.1.4.1.2011.6.139.18.1.4.2.1',
  'hwWlanStaOnlineFailReasonCode' => '1.3.6.1.4.1.2011.6.139.18.1.4.2.1.1',
  'hwWlanStaOnlineFailReasonDesc' => '1.3.6.1.4.1.2011.6.139.18.1.4.2.1.2',
  'hwWlanStaOnlineFailReasonCount' => '1.3.6.1.4.1.2011.6.139.18.1.4.2.1.3',
  'hwWlanStaOfflineInfo' => '1.3.6.1.4.1.2011.6.139.18.1.5',
  'hwWlanStaOfflineTable' => '1.3.6.1.4.1.2011.6.139.18.1.5.1',
  'hwWlanStaOfflineEntry' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1',
  'hwWlanStaOfflineMacAddress' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.1',
  'hwWlanStaOfflineReasonIndex' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.2',
  'hwWlanStaOfflineApMac' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.3',
  'hwWlanStaOfflineApName' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.4',
  'hwWlanStaOfflineRadioId' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.5',
  'hwWlanStaOfflineWlanId' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.6',
  'hwWlanStaOfflineLastFailTime' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.7',
  'hwWlanStaOfflineReason' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.8',
  'hwWlanStaOfflineSsid' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.9',
  'hwWlanStaOfflineFailRowStatus' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.10',
  'hwWlanStaOfflineApId' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.11',
  'hwWlanStaOfflineDevType' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.12',
  'hwWlanStaOfflineAcId' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.13',
  'hwWlanStaOfflineAcName' => '1.3.6.1.4.1.2011.6.139.18.1.5.1.1.14',
  'hwWlanStaOfflineReasonTable' => '1.3.6.1.4.1.2011.6.139.18.1.5.2',
  'hwWlanStaOfflineReasonEntry' => '1.3.6.1.4.1.2011.6.139.18.1.5.2.1',
  'hwWlanStaOfflineReasonCode' => '1.3.6.1.4.1.2011.6.139.18.1.5.2.1.1',
  'hwWlanStaOfflineReasonDesc' => '1.3.6.1.4.1.2011.6.139.18.1.5.2.1.2',
  'hwWlanStaOfflineReasonCount' => '1.3.6.1.4.1.2011.6.139.18.1.5.2.1.3',
  'hwWlanStaRoamInfo' => '1.3.6.1.4.1.2011.6.139.18.1.6',
  'hwWlanStaRoamTraceTable' => '1.3.6.1.4.1.2011.6.139.18.1.6.1',
  'hwWlanStaRoamTraceEntry' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1',
  'hwWlanStaRoamTraceStaMac' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.1',
  'hwWlanStaRoamTraceIndex' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.2',
  'hwWlanStaRoamTraceTime' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.3',
  'hwWlanStaRoamTraceAcIP' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.4',
  'hwWlanStaRoamTraceAcIPv6' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.5',
  'hwWlanStaRoamTraceApName' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.6',
  'hwWlanStaRoamTraceRadioId' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.7',
  'hwWlanStaRoamTraceBssid' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.8',
  'hwWlanStaRoamTraceInRate' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.9',
  'hwWlanStaRoamTraceOutRate' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.10',
  'hwWlanStaRoamTraceInRssi' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.11',
  'hwWlanStaRoamTraceOutRssi' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.12',
  'hwWlanStaRoamTraceRoamType' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.13',
  'hwWlanStaRoamTraceRoamTypeDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaRoamTraceRoamType',
  'hwWlanStaRoamTraceApId' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.14',
  'hwWlanStaRoamTraceInfo' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.15',
  'hwWlanStaRoamTraceInfoDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanStaRoamTraceInfo',
  'hwWlanStaRoamTraceMemberAcIP' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.16',
  'hwWlanStaRoamTraceMemberAcIPv6' => '1.3.6.1.4.1.2011.6.139.18.1.6.1.1.17',
  'hwWlanStaAcL3RoamStatisticsTable' => '1.3.6.1.4.1.2011.6.139.18.1.6.2',
  'hwWlanStaAcL3RoamStatisticsEntry' => '1.3.6.1.4.1.2011.6.139.18.1.6.2.1',
  'hwWlanStaAcL3RoamStatisticAcIndex' => '1.3.6.1.4.1.2011.6.139.18.1.6.2.1.1',
  'hwWlanStaAcL3RoamStatisticAcIP' => '1.3.6.1.4.1.2011.6.139.18.1.6.2.1.2',
  'hwWlanStaAcL3RoamStatisticAcIPv6' => '1.3.6.1.4.1.2011.6.139.18.1.6.2.1.3',
  'hwWlanStaAcL3RoamStatisticRoamInCnt' => '1.3.6.1.4.1.2011.6.139.18.1.6.2.1.4',
  'hwWlanStaAcL3RoamStatisticRoamOutCnt' => '1.3.6.1.4.1.2011.6.139.18.1.6.2.1.5',
  'hwWlanStaAcL3RoamStatisticAcDescription' => '1.3.6.1.4.1.2011.6.139.18.1.6.2.1.6',
  'hwWlanStaApL3RoamStatisticsTable' => '1.3.6.1.4.1.2011.6.139.18.1.6.3',
  'hwWlanStaApL3RoamStatisticsEntry' => '1.3.6.1.4.1.2011.6.139.18.1.6.3.1',
  'hwWlanStaApL3RoamStatisticApMac' => '1.3.6.1.4.1.2011.6.139.18.1.6.3.1.1',
  'hwWlanStaApL3RoamStatisticApName' => '1.3.6.1.4.1.2011.6.139.18.1.6.3.1.2',
  'hwWlanStaApL3RoamStatisticRoamInCnt' => '1.3.6.1.4.1.2011.6.139.18.1.6.3.1.3',
  'hwWlanStaApL3RoamStatisticRoamOutCnt' => '1.3.6.1.4.1.2011.6.139.18.1.6.3.1.4',
  'hwWlanStaApL3RoamStatisticApId' => '1.3.6.1.4.1.2011.6.139.18.1.6.3.1.5',
  'hwWlanNaviACStationTable' => '1.3.6.1.4.1.2011.6.139.18.1.7',
  'hwWlanNaviACStationEntry' => '1.3.6.1.4.1.2011.6.139.18.1.7.1',
  'hwWlanNaviACStationMac' => '1.3.6.1.4.1.2011.6.139.18.1.7.1.1',
  'hwWlanNaviACStationIPAddress' => '1.3.6.1.4.1.2011.6.139.18.1.7.1.2',
  'hwWlanNaviACStationIPv6Address' => '1.3.6.1.4.1.2011.6.139.18.1.7.1.3',
  'hwWlanNaviACStationOnlineTime' => '1.3.6.1.4.1.2011.6.139.18.1.7.1.4',
  'hwWlanNaviACStationAuthMethod' => '1.3.6.1.4.1.2011.6.139.18.1.7.1.5',
  'hwWlanNaviACStationAuthMethodDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanNaviACStationAuthMethod',
  'hwWlanNaviAcStationVlanID' => '1.3.6.1.4.1.2011.6.139.18.1.7.1.6',
  'hwWlanNaviAcStationState' => '1.3.6.1.4.1.2011.6.139.18.1.7.1.7',
  'hwWlanNaviAcStationStateDefinition' => 'HUAWEI-WLAN-STATION-MIB::hwWlanNaviAcStationState',
  'hwWlanNaviACStationLocalACID' => '1.3.6.1.4.1.2011.6.139.18.1.7.1.8',
  'hwWlanNaviACStationWlanId' => '1.3.6.1.4.1.2011.6.139.18.1.7.1.9',
  'hwWlanStationConformance' => '1.3.6.1.4.1.2011.6.139.18.2',
  'hwWlanStationCompliances' => '1.3.6.1.4.1.2011.6.139.18.2.1',
  'hwWlanStationObjectGroups' => '1.3.6.1.4.1.2011.6.139.18.2.2',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::definitions->{'HUAWEI-WLAN-STATION-MIB'} = {
  'hwWlanStaStatOperMode' => {
    '1' => 'invalid',
    '2' => 'clearstatistic',
  },
  'hwWlanStaVHTTxBFCapable' => {
    '1' => 'nonsupport',
    '2' => 'support',
  },
  'hwWlanStaDelayStatus' => {
    '1' => 'delay',
    '2' => 'normal',
  },
  'hwWlanStaQosMode' => {
    '1' => 'wmm',
    '2' => 'null',
  },
  'hwWlanStaEncryptMethod' => {
    '1' => 'wpiSms4',
    '2' => 'wep40',
    '3' => 'wep104',
    '4' => 'tkip',
    '5' => 'aes',
    '6' => 'none',
  },
  'hwWlanStaRoamStatus' => {
    '1' => 'no',
    '2' => 'yes',
  },
  'hwWlanStaStatus' => {
    '1' => 'age',
    '2' => 'associatedNotAuthenticated',
    '3' => 'associatedAndAuthenticated',
    '4' => 'roam',
    '5' => 'backup',
  },
  'hwWlanStaHtMode' => {
    '1' => 'invalid',
    '2' => 'ht40',
    '3' => 'ht20',
    '4' => 'ht80',
    '5' => 'ht160',
  },
  'hwWlanNaviAcStationState' => {
    '1' => 'assoc',
    '2' => 'authing',
    '3' => 'run',
    '4' => 'delete',
  },
  'hwWlanStaRfMode' => {
    '0' => 'unknown',
    '1' => 'dotb',
    '2' => 'dotg',
    '3' => 'dotn',
    '4' => 'dota',
    '5' => 'dotac',
    '6' => 'dotax',
  },
  'hwWlanStaRoamTraceRoamType' => {
    '1' => 'l2',
    '2' => 'l3',
    '3' => 'none',
  },
  'hwWlanStaFailCodeType' => {
    '1' => 'reasonCode',
    '2' => 'statusCode',
  },
  'hwWlanNaviACStationAuthMethod' => {
    '1' => 'wepOpenSystem',
    '2' => 'wepOpenSystemMac',
    '3' => 'wepOpenSystem8021X',
    '4' => 'wepOpenSystemPortal',
    '5' => 'wepShareKey',
    '6' => 'wepShareKeyMac',
    '7' => 'wepShareKey8021X',
    '8' => 'wepShareKeyPortal',
    '9' => 'wpa8021X',
    '10' => 'wpaPreShareKey',
    '11' => 'wpaPskMac',
    '12' => 'wpaPskPortal',
    '13' => 'wpa2Dot1x',
    '14' => 'wpa2PreShareKey',
    '15' => 'wpa2PskMac',
    '16' => 'wpa2PskPortal',
    '17' => 'wapiCertification',
    '18' => 'wapiPreShareKey',
    '19' => 'wpaWpa2PreShareKey',
    '20' => 'wpaWpa2PskMac',
    '21' => 'wpaWpa2PskPortal',
    '22' => 'wpaWpa2Dot1x',
    '23' => 'wapiPskPortal',
    '24' => 'macDot1x',
    '25' => 'wepShareKey8021XMac',
    '26' => 'wpa8021XMac',
    '27' => 'wpa2Dot1xMac',
    '28' => 'wpaWpa2Dot1xMac',
    '29' => 'wepOpenSystemPortalMac',
    '30' => 'wepShareKeyPortalMac',
    '31' => 'wpaPskPortalMac',
    '32' => 'wpa2PskPortalMac',
    '33' => 'wpaWpa2PskPortalMac',
    '34' => 'wapiPskPortalMac',
    '35' => 'wpaPpsk',
    '36' => 'wpaPpskMac',
    '37' => 'wpaPpskPortal',
    '38' => 'wpaPpskPortalMac',
    '39' => 'wpa2Ppsk',
    '40' => 'wpa2PpskMac',
    '41' => 'wpa2PpskPortal',
    '42' => 'wpa2PpskPortalMac',
    '43' => 'wpaWpa2Ppsk',
    '44' => 'wpaWpa2PpskMac',
    '45' => 'wpaWpa2PpskPortal',
    '46' => 'wpaWpa2PpskPortalMac',
    '47' => 'wep8021X',
  },
  'hwWlanStaAuthenMethod' => {
    '1' => 'wepOpenSystem',
    '2' => 'wepOpenSystemMac',
    '3' => 'wepOpenSystem8021X',
    '4' => 'wepOpenSystemPortal',
    '5' => 'wepShareKey',
    '6' => 'wepShareKeyMac',
    '7' => 'wepShareKey8021X',
    '8' => 'wepShareKeyPortal',
    '9' => 'wpa8021X',
    '10' => 'wpaPreShareKey',
    '11' => 'wpaPskMac',
    '12' => 'wpaPskPortal',
    '13' => 'wpa2Dot1x',
    '14' => 'wpa2PreShareKey',
    '15' => 'wpa2PskMac',
    '16' => 'wpa2PskPortal',
    '17' => 'wapiCertification',
    '18' => 'wapiPreShareKey',
    '19' => 'wpaWpa2PreShareKey',
    '20' => 'wpaWpa2PskMac',
    '21' => 'wpaWpa2PskPortal',
    '22' => 'wpaWpa2Dot1x',
    '23' => 'wapiPskPortal',
    '24' => 'macDot1x',
    '25' => 'wepShareKey8021XMac',
    '26' => 'wpa8021XMac',
    '27' => 'wpa2Dot1xMac',
    '28' => 'wpaWpa2Dot1xMac',
    '29' => 'wepOpenSystemPortalMac',
    '30' => 'wepShareKeyPortalMac',
    '31' => 'wpaPskPortalMac',
    '32' => 'wpa2PskPortalMac',
    '33' => 'wpaWpa2PskPortalMac',
    '34' => 'wapiPskPortalMac',
    '35' => 'wpaPpsk',
    '36' => 'wpaPpskMac',
    '37' => 'wpaPpskPortal',
    '38' => 'wpaPpskPortalMac',
    '39' => 'wpa2Ppsk',
    '40' => 'wpa2PpskMac',
    '41' => 'wpa2PpskPortal',
    '42' => 'wpa2PpskPortalMac',
    '43' => 'wpaWpa2Ppsk',
    '44' => 'wpaWpa2PpskMac',
    '45' => 'wpaWpa2PpskPortal',
    '46' => 'wpaWpa2PpskPortalMac',
    '47' => 'wep8021X',
  },
  'hwWlanStaMUMIMOCapable' => {
    '1' => 'nonsupport',
    '2' => 'support',
  },
  'hwWlanStaVHTCapable' => {
    '1' => 'nonsupport',
    '2' => 'support',
  },
  'hwWlanStaShortGIStatus' => {
    '1' => 'nonsupport',
    '2' => 'support',
  },
  'hwWlanStaRoamTraceInfo' => {
    '0' => 'normal',
    '1' => 'sameFrequencyNetwork',
    '2' => 'pmkCacheRoam',
    '3' => 'dot11rRoam',
    '4' => 'dot11rOverthedsRoam',
    '5' => 'dot11rPrivateRoam',
  },
};
