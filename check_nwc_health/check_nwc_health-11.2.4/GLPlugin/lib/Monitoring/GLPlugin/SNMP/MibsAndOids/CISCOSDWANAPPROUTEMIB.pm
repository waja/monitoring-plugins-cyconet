package Monitoring::GLPlugin::SNMP::MibsAndOids::CISCOSDWANAPPROUTEMIB;

$Monitoring::GLPlugin::SNMP::MibsAndOids::origin->{'CISCO-SDWAN-APP-ROUTE-MIB'} = {
  url => '',
  name => 'CISCO-SDWAN-APP-ROUTE-MIB',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::mib_ids->{'CISCO-SDWAN-APP-ROUTE-MIB'} =
  '1.3.6.1.4.1.9.9.1001';

$Monitoring::GLPlugin::SNMP::MibsAndOids::mibs_and_oids->{'CISCO-SDWAN-APP-ROUTE-MIB'} = {
  'ciscoSdwanAppRouteMIB' => '1.3.6.1.4.1.9.9.1001',
  'ciscoSdwanAppRouteMIBObjects' => '1.3.6.1.4.1.9.9.1001.1',
  'appRouteStatisticsTable' => '1.3.6.1.4.1.9.9.1001.1.2',
  'appRouteStatisticsEntry' => '1.3.6.1.4.1.9.9.1001.1.2.1',
  'appRouteStatisticsSrcIp' => '1.3.6.1.4.1.9.9.1001.1.2.1.1',
  'appRouteStatisticsDstIp' => '1.3.6.1.4.1.9.9.1001.1.2.1.2',
  'appRouteStatisticsProto' => '1.3.6.1.4.1.9.9.1001.1.2.1.3',
  'appRouteStatisticsProtoDefinition' => 'CISCO-SDWAN-APP-ROUTE-MIB::appRouteStatisticsProto',
  'appRouteStatisticsSrcPort' => '1.3.6.1.4.1.9.9.1001.1.2.1.4',
  'appRouteStatisticsDstPort' => '1.3.6.1.4.1.9.9.1001.1.2.1.5',
  'appRouteStatisticsRemoteSystemIp' => '1.3.6.1.4.1.9.9.1001.1.2.1.6',
  'appRouteStatisticsLocalColor' => '1.3.6.1.4.1.9.9.1001.1.2.1.7',
  'appRouteStatisticsLocalColorDefinition' => 'CISCO-SDWAN-APP-ROUTE-MIB::appRouteStatisticsLocalColor',
  'appRouteStatisticsRemoteColor' => '1.3.6.1.4.1.9.9.1001.1.2.1.8',
  'appRouteStatisticsRemoteColorDefinition' => 'CISCO-SDWAN-APP-ROUTE-MIB::appRouteStatisticsRemoteColor',
  'appRouteSlaClassTable' => '1.3.6.1.4.1.9.9.1001.1.4',
  'appRouteSlaClassEntry' => '1.3.6.1.4.1.9.9.1001.1.4.1',
  'appRouteSlaClassIndex' => '1.3.6.1.4.1.9.9.1001.1.4.1.1',
  'appRouteSlaClassName' => '1.3.6.1.4.1.9.9.1001.1.4.1.2',
  'appRouteSlaClassLoss' => '1.3.6.1.4.1.9.9.1001.1.4.1.3',
  'appRouteSlaClassLatency' => '1.3.6.1.4.1.9.9.1001.1.4.1.4',
  'appRouteSlaClassJitter' => '1.3.6.1.4.1.9.9.1001.1.4.1.5',
  'appRouteStatisticsAppProbeClassTable' => '1.3.6.1.4.1.9.9.1001.1.5',
  'appRouteStatisticsAppProbeClassEntry' => '1.3.6.1.4.1.9.9.1001.1.5.1',
  'appRouteStatisticsAppProbeClassName' => '1.3.6.1.4.1.9.9.1001.1.5.1.1',
  'appRouteStatisticsAppProbeClassMeanLoss' => '1.3.6.1.4.1.9.9.1001.1.5.1.2',
  'appRouteStatisticsAppProbeClassMeanLatency' => '1.3.6.1.4.1.9.9.1001.1.5.1.3',
  'appRouteStatisticsAppProbeClassMeanJitter' => '1.3.6.1.4.1.9.9.1001.1.5.1.4',
  'appRouteStatisticsAppProbeClassIntervalTable' => '1.3.6.1.4.1.9.9.1001.1.6',
  'appRouteStatisticsAppProbeClassIntervalEntry' => '1.3.6.1.4.1.9.9.1001.1.6.1',
  'appRouteStatisticsAppProbeClassIntervalIndex' => '1.3.6.1.4.1.9.9.1001.1.6.1.1',
  'appRouteStatisticsAppProbeClassIntervalTotalPackets' => '1.3.6.1.4.1.9.9.1001.1.6.1.2',
  'appRouteStatisticsAppProbeClassIntervalLoss' => '1.3.6.1.4.1.9.9.1001.1.6.1.3',
  'appRouteStatisticsAppProbeClassIntervalAverageLatency' => '1.3.6.1.4.1.9.9.1001.1.6.1.4',
  'appRouteStatisticsAppProbeClassIntervalAverageJitter' => '1.3.6.1.4.1.9.9.1001.1.6.1.5',
  'appRouteStatisticsAppProbeClassIntervalTxDataPkts' => '1.3.6.1.4.1.9.9.1001.1.6.1.6',
  'appRouteStatisticsAppProbeClassIntervalRxDataPkts' => '1.3.6.1.4.1.9.9.1001.1.6.1.7',
  'appRouteStatisticsAppProbeClassIntervalIpv6TxDataPkts' => '1.3.6.1.4.1.9.9.1001.1.6.1.8',
  'appRouteStatisticsAppProbeClassIntervalIpv6RxDataPkts' => '1.3.6.1.4.1.9.9.1001.1.6.1.9',
  'ciscoSdwanAppRouteMIBConform' => '1.3.6.1.4.1.9.9.1001.3',
  'ciscoSdwanAppRouteMIBCompliances' => '1.3.6.1.4.1.9.9.1001.3.1',
  'ciscoSdwanAppRouteMIBGroups' => '1.3.6.1.4.1.9.9.1001.3.2',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::definitions->{'CISCO-SDWAN-APP-ROUTE-MIB'} = {
  'appRouteStatisticsRemoteColor' => {
    '1' => 'default',
    '2' => 'mpls',
    '3' => 'metroEthernet',
    '4' => 'bizInternet',
    '5' => 'publicInternet',
    '6' => 'lte',
    '7' => 'threeG',
    '8' => 'red',
    '9' => 'green',
    '10' => 'blue',
    '11' => 'gold',
    '12' => 'silver',
    '13' => 'bronze',
    '14' => 'custom1',
    '15' => 'custom2',
    '16' => 'custom3',
    '17' => 'private1',
    '18' => 'private2',
    '19' => 'private3',
    '20' => 'private4',
    '21' => 'private5',
    '22' => 'private6',
  },
  'appRouteStatisticsLocalColor' => {
    '1' => 'default',
    '2' => 'mpls',
    '3' => 'metroEthernet',
    '4' => 'bizInternet',
    '5' => 'publicInternet',
    '6' => 'lte',
    '7' => 'threeG',
    '8' => 'red',
    '9' => 'green',
    '10' => 'blue',
    '11' => 'gold',
    '12' => 'silver',
    '13' => 'bronze',
    '14' => 'custom1',
    '15' => 'custom2',
    '16' => 'custom3',
    '17' => 'private1',
    '18' => 'private2',
    '19' => 'private3',
    '20' => 'private4',
    '21' => 'private5',
    '22' => 'private6',
  },
  'appRouteStatisticsProto' => {
    '1' => 'gre',
    '2' => 'ipsec',
  },
};