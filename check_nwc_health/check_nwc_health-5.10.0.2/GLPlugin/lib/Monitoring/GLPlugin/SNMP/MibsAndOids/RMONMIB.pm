package Monitoring::GLPlugin::SNMP::MibsAndOids::RMONMIB;

$Monitoring::GLPlugin::SNMP::MibsAndOids::origin->{'RMON-MIB'} = {
  url => 'https://www.ietf.org/rfc/rfc1271.txt',
  name => 'RMON-MIB',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::mib_ids->{'RMON-MIB'} =
    '1.3.6.1.2.1.16';

$Monitoring::GLPlugin::SNMP::MibsAndOids::mibs_and_oids->{'RMON-MIB'} = {
  rmon => '1.3.6.1.2.1.16',
  rmonEventsV2 => '1.3.6.1.2.1.16.0',
  statistics => '1.3.6.1.2.1.16.1',
  etherStatsTable => '1.3.6.1.2.1.16.1.1',
  etherStatsEntry => '1.3.6.1.2.1.16.1.1.1',
  etherStatsIndex => '1.3.6.1.2.1.16.1.1.1.1',
  etherStatsDataSource => '1.3.6.1.2.1.16.1.1.1.2',
  etherStatsDropEvents => '1.3.6.1.2.1.16.1.1.1.3',
  etherStatsOctets => '1.3.6.1.2.1.16.1.1.1.4',
  etherStatsPkts => '1.3.6.1.2.1.16.1.1.1.5',
  etherStatsBroadcastPkts => '1.3.6.1.2.1.16.1.1.1.6',
  etherStatsMulticastPkts => '1.3.6.1.2.1.16.1.1.1.7',
  etherStatsCRCAlignErrors => '1.3.6.1.2.1.16.1.1.1.8',
  etherStatsUndersizePkts => '1.3.6.1.2.1.16.1.1.1.9',
  etherStatsOversizePkts => '1.3.6.1.2.1.16.1.1.1.10',
  etherStatsFragments => '1.3.6.1.2.1.16.1.1.1.11',
  etherStatsJabbers => '1.3.6.1.2.1.16.1.1.1.12',
  etherStatsCollisions => '1.3.6.1.2.1.16.1.1.1.13',
  etherStatsPkts64Octets => '1.3.6.1.2.1.16.1.1.1.14',
  etherStatsPkts65to127Octets => '1.3.6.1.2.1.16.1.1.1.15',
  etherStatsPkts128to255Octets => '1.3.6.1.2.1.16.1.1.1.16',
  etherStatsPkts256to511Octets => '1.3.6.1.2.1.16.1.1.1.17',
  etherStatsPkts512to1023Octets => '1.3.6.1.2.1.16.1.1.1.18',
  etherStatsPkts1024to1518Octets => '1.3.6.1.2.1.16.1.1.1.19',
  etherStatsOwner => '1.3.6.1.2.1.16.1.1.1.20',
  etherStatsStatus => '1.3.6.1.2.1.16.1.1.1.21',
  etherStatsStatusDefinition => 'RMON-MIB::EntryStatus',
  history => '1.3.6.1.2.1.16.2',
  historyControlTable => '1.3.6.1.2.1.16.2.1',
  historyControlEntry => '1.3.6.1.2.1.16.2.1.1',
  historyControlIndex => '1.3.6.1.2.1.16.2.1.1.1',
  historyControlDataSource => '1.3.6.1.2.1.16.2.1.1.2',
  historyControlBucketsRequested => '1.3.6.1.2.1.16.2.1.1.3',
  historyControlBucketsGranted => '1.3.6.1.2.1.16.2.1.1.4',
  historyControlInterval => '1.3.6.1.2.1.16.2.1.1.5',
  historyControlOwner => '1.3.6.1.2.1.16.2.1.1.6',
  historyControlStatus => '1.3.6.1.2.1.16.2.1.1.7',
  historyControlStatusDefinition => 'RMON-MIB::EntryStatus',
  etherHistoryTable => '1.3.6.1.2.1.16.2.2',
  etherHistoryEntry => '1.3.6.1.2.1.16.2.2.1',
  etherHistoryIndex => '1.3.6.1.2.1.16.2.2.1.1',
  etherHistorySampleIndex => '1.3.6.1.2.1.16.2.2.1.2',
  etherHistoryIntervalStart => '1.3.6.1.2.1.16.2.2.1.3',
  etherHistoryDropEvents => '1.3.6.1.2.1.16.2.2.1.4',
  etherHistoryOctets => '1.3.6.1.2.1.16.2.2.1.5',
  etherHistoryPkts => '1.3.6.1.2.1.16.2.2.1.6',
  etherHistoryBroadcastPkts => '1.3.6.1.2.1.16.2.2.1.7',
  etherHistoryMulticastPkts => '1.3.6.1.2.1.16.2.2.1.8',
  etherHistoryCRCAlignErrors => '1.3.6.1.2.1.16.2.2.1.9',
  etherHistoryUndersizePkts => '1.3.6.1.2.1.16.2.2.1.10',
  etherHistoryOversizePkts => '1.3.6.1.2.1.16.2.2.1.11',
  etherHistoryFragments => '1.3.6.1.2.1.16.2.2.1.12',
  etherHistoryJabbers => '1.3.6.1.2.1.16.2.2.1.13',
  etherHistoryCollisions => '1.3.6.1.2.1.16.2.2.1.14',
  etherHistoryUtilization => '1.3.6.1.2.1.16.2.2.1.15',
  alarm => '1.3.6.1.2.1.16.3',
  alarmTable => '1.3.6.1.2.1.16.3.1',
  alarmEntry => '1.3.6.1.2.1.16.3.1.1',
  alarmIndex => '1.3.6.1.2.1.16.3.1.1.1',
  alarmInterval => '1.3.6.1.2.1.16.3.1.1.2',
  alarmVariable => '1.3.6.1.2.1.16.3.1.1.3',
  alarmSampleType => '1.3.6.1.2.1.16.3.1.1.4',
  alarmSampleTypeDefinition => 'RMON-MIB::alarmSampleType',
  alarmValue => '1.3.6.1.2.1.16.3.1.1.5',
  alarmStartupAlarm => '1.3.6.1.2.1.16.3.1.1.6',
  alarmStartupAlarmDefinition => 'RMON-MIB::alarmStartupAlarm',
  alarmRisingThreshold => '1.3.6.1.2.1.16.3.1.1.7',
  alarmFallingThreshold => '1.3.6.1.2.1.16.3.1.1.8',
  alarmRisingEventIndex => '1.3.6.1.2.1.16.3.1.1.9',
  alarmFallingEventIndex => '1.3.6.1.2.1.16.3.1.1.10',
  alarmOwner => '1.3.6.1.2.1.16.3.1.1.11',
  alarmStatus => '1.3.6.1.2.1.16.3.1.1.12',
  alarmStatusDefinition => 'RMON-MIB::EntryStatus',
  hosts => '1.3.6.1.2.1.16.4',
  hostControlTable => '1.3.6.1.2.1.16.4.1',
  hostControlEntry => '1.3.6.1.2.1.16.4.1.1',
  hostControlIndex => '1.3.6.1.2.1.16.4.1.1.1',
  hostControlDataSource => '1.3.6.1.2.1.16.4.1.1.2',
  hostControlTableSize => '1.3.6.1.2.1.16.4.1.1.3',
  hostControlLastDeleteTime => '1.3.6.1.2.1.16.4.1.1.4',
  hostControlOwner => '1.3.6.1.2.1.16.4.1.1.5',
  hostControlStatus => '1.3.6.1.2.1.16.4.1.1.6',
  hostControlStatusDefinition => 'RMON-MIB::EntryStatus',
  hostTable => '1.3.6.1.2.1.16.4.2',
  hostEntry => '1.3.6.1.2.1.16.4.2.1',
  hostAddress => '1.3.6.1.2.1.16.4.2.1.1',
  hostCreationOrder => '1.3.6.1.2.1.16.4.2.1.2',
  hostIndex => '1.3.6.1.2.1.16.4.2.1.3',
  hostInPkts => '1.3.6.1.2.1.16.4.2.1.4',
  hostOutPkts => '1.3.6.1.2.1.16.4.2.1.5',
  hostInOctets => '1.3.6.1.2.1.16.4.2.1.6',
  hostOutOctets => '1.3.6.1.2.1.16.4.2.1.7',
  hostOutErrors => '1.3.6.1.2.1.16.4.2.1.8',
  hostOutBroadcastPkts => '1.3.6.1.2.1.16.4.2.1.9',
  hostOutMulticastPkts => '1.3.6.1.2.1.16.4.2.1.10',
  hostTimeTable => '1.3.6.1.2.1.16.4.3',
  hostTimeEntry => '1.3.6.1.2.1.16.4.3.1',
  hostTimeAddress => '1.3.6.1.2.1.16.4.3.1.1',
  hostTimeCreationOrder => '1.3.6.1.2.1.16.4.3.1.2',
  hostTimeIndex => '1.3.6.1.2.1.16.4.3.1.3',
  hostTimeInPkts => '1.3.6.1.2.1.16.4.3.1.4',
  hostTimeOutPkts => '1.3.6.1.2.1.16.4.3.1.5',
  hostTimeInOctets => '1.3.6.1.2.1.16.4.3.1.6',
  hostTimeOutOctets => '1.3.6.1.2.1.16.4.3.1.7',
  hostTimeOutErrors => '1.3.6.1.2.1.16.4.3.1.8',
  hostTimeOutBroadcastPkts => '1.3.6.1.2.1.16.4.3.1.9',
  hostTimeOutMulticastPkts => '1.3.6.1.2.1.16.4.3.1.10',
  hostTopN => '1.3.6.1.2.1.16.5',
  hostTopNControlTable => '1.3.6.1.2.1.16.5.1',
  hostTopNControlEntry => '1.3.6.1.2.1.16.5.1.1',
  hostTopNControlIndex => '1.3.6.1.2.1.16.5.1.1.1',
  hostTopNHostIndex => '1.3.6.1.2.1.16.5.1.1.2',
  hostTopNRateBase => '1.3.6.1.2.1.16.5.1.1.3',
  hostTopNRateBaseDefinition => 'RMON-MIB::hostTopNRateBase',
  hostTopNTimeRemaining => '1.3.6.1.2.1.16.5.1.1.4',
  hostTopNDuration => '1.3.6.1.2.1.16.5.1.1.5',
  hostTopNRequestedSize => '1.3.6.1.2.1.16.5.1.1.6',
  hostTopNGrantedSize => '1.3.6.1.2.1.16.5.1.1.7',
  hostTopNStartTime => '1.3.6.1.2.1.16.5.1.1.8',
  hostTopNOwner => '1.3.6.1.2.1.16.5.1.1.9',
  hostTopNStatus => '1.3.6.1.2.1.16.5.1.1.10',
  hostTopNStatusDefinition => 'RMON-MIB::EntryStatus',
  hostTopNTable => '1.3.6.1.2.1.16.5.2',
  hostTopNEntry => '1.3.6.1.2.1.16.5.2.1',
  hostTopNReport => '1.3.6.1.2.1.16.5.2.1.1',
  hostTopNIndex => '1.3.6.1.2.1.16.5.2.1.2',
  hostTopNAddress => '1.3.6.1.2.1.16.5.2.1.3',
  hostTopNRate => '1.3.6.1.2.1.16.5.2.1.4',
  matrix => '1.3.6.1.2.1.16.6',
  matrixControlTable => '1.3.6.1.2.1.16.6.1',
  matrixControlEntry => '1.3.6.1.2.1.16.6.1.1',
  matrixControlIndex => '1.3.6.1.2.1.16.6.1.1.1',
  matrixControlDataSource => '1.3.6.1.2.1.16.6.1.1.2',
  matrixControlTableSize => '1.3.6.1.2.1.16.6.1.1.3',
  matrixControlLastDeleteTime => '1.3.6.1.2.1.16.6.1.1.4',
  matrixControlOwner => '1.3.6.1.2.1.16.6.1.1.5',
  matrixControlStatus => '1.3.6.1.2.1.16.6.1.1.6',
  matrixControlStatusDefinition => 'RMON-MIB::EntryStatus',
  matrixSDTable => '1.3.6.1.2.1.16.6.2',
  matrixSDEntry => '1.3.6.1.2.1.16.6.2.1',
  matrixSDSourceAddress => '1.3.6.1.2.1.16.6.2.1.1',
  matrixSDDestAddress => '1.3.6.1.2.1.16.6.2.1.2',
  matrixSDIndex => '1.3.6.1.2.1.16.6.2.1.3',
  matrixSDPkts => '1.3.6.1.2.1.16.6.2.1.4',
  matrixSDOctets => '1.3.6.1.2.1.16.6.2.1.5',
  matrixSDErrors => '1.3.6.1.2.1.16.6.2.1.6',
  matrixDSTable => '1.3.6.1.2.1.16.6.3',
  matrixDSEntry => '1.3.6.1.2.1.16.6.3.1',
  matrixDSSourceAddress => '1.3.6.1.2.1.16.6.3.1.1',
  matrixDSDestAddress => '1.3.6.1.2.1.16.6.3.1.2',
  matrixDSIndex => '1.3.6.1.2.1.16.6.3.1.3',
  matrixDSPkts => '1.3.6.1.2.1.16.6.3.1.4',
  matrixDSOctets => '1.3.6.1.2.1.16.6.3.1.5',
  matrixDSErrors => '1.3.6.1.2.1.16.6.3.1.6',
  filter => '1.3.6.1.2.1.16.7',
  filterTable => '1.3.6.1.2.1.16.7.1',
  filterEntry => '1.3.6.1.2.1.16.7.1.1',
  filterIndex => '1.3.6.1.2.1.16.7.1.1.1',
  filterChannelIndex => '1.3.6.1.2.1.16.7.1.1.2',
  filterPktDataOffset => '1.3.6.1.2.1.16.7.1.1.3',
  filterPktData => '1.3.6.1.2.1.16.7.1.1.4',
  filterPktDataMask => '1.3.6.1.2.1.16.7.1.1.5',
  filterPktDataNotMask => '1.3.6.1.2.1.16.7.1.1.6',
  filterPktStatus => '1.3.6.1.2.1.16.7.1.1.7',
  filterPktStatusMask => '1.3.6.1.2.1.16.7.1.1.8',
  filterPktStatusNotMask => '1.3.6.1.2.1.16.7.1.1.9',
  filterOwner => '1.3.6.1.2.1.16.7.1.1.10',
  filterStatus => '1.3.6.1.2.1.16.7.1.1.11',
  filterStatusDefinition => 'RMON-MIB::EntryStatus',
  channelTable => '1.3.6.1.2.1.16.7.2',
  channelEntry => '1.3.6.1.2.1.16.7.2.1',
  channelIndex => '1.3.6.1.2.1.16.7.2.1.1',
  channelIfIndex => '1.3.6.1.2.1.16.7.2.1.2',
  channelAcceptType => '1.3.6.1.2.1.16.7.2.1.3',
  channelAcceptTypeDefinition => 'RMON-MIB::channelAcceptType',
  channelDataControl => '1.3.6.1.2.1.16.7.2.1.4',
  channelDataControlDefinition => 'RMON-MIB::channelDataControl',
  channelTurnOnEventIndex => '1.3.6.1.2.1.16.7.2.1.5',
  channelTurnOffEventIndex => '1.3.6.1.2.1.16.7.2.1.6',
  channelEventIndex => '1.3.6.1.2.1.16.7.2.1.7',
  channelEventStatus => '1.3.6.1.2.1.16.7.2.1.8',
  channelEventStatusDefinition => 'RMON-MIB::channelEventStatus',
  channelMatches => '1.3.6.1.2.1.16.7.2.1.9',
  channelDescription => '1.3.6.1.2.1.16.7.2.1.10',
  channelOwner => '1.3.6.1.2.1.16.7.2.1.11',
  channelStatus => '1.3.6.1.2.1.16.7.2.1.12',
  channelStatusDefinition => 'RMON-MIB::EntryStatus',
  capture => '1.3.6.1.2.1.16.8',
  bufferControlTable => '1.3.6.1.2.1.16.8.1',
  bufferControlEntry => '1.3.6.1.2.1.16.8.1.1',
  bufferControlIndex => '1.3.6.1.2.1.16.8.1.1.1',
  bufferControlChannelIndex => '1.3.6.1.2.1.16.8.1.1.2',
  bufferControlFullStatus => '1.3.6.1.2.1.16.8.1.1.3',
  bufferControlFullStatusDefinition => 'RMON-MIB::bufferControlFullStatus',
  bufferControlFullAction => '1.3.6.1.2.1.16.8.1.1.4',
  bufferControlFullActionDefinition => 'RMON-MIB::bufferControlFullAction',
  bufferControlCaptureSliceSize => '1.3.6.1.2.1.16.8.1.1.5',
  bufferControlDownloadSliceSize => '1.3.6.1.2.1.16.8.1.1.6',
  bufferControlDownloadOffset => '1.3.6.1.2.1.16.8.1.1.7',
  bufferControlMaxOctetsRequested => '1.3.6.1.2.1.16.8.1.1.8',
  bufferControlMaxOctetsGranted => '1.3.6.1.2.1.16.8.1.1.9',
  bufferControlCapturedPackets => '1.3.6.1.2.1.16.8.1.1.10',
  bufferControlTurnOnTime => '1.3.6.1.2.1.16.8.1.1.11',
  bufferControlOwner => '1.3.6.1.2.1.16.8.1.1.12',
  bufferControlStatus => '1.3.6.1.2.1.16.8.1.1.13',
  bufferControlStatusDefinition => 'RMON-MIB::EntryStatus',
  captureBufferTable => '1.3.6.1.2.1.16.8.2',
  captureBufferEntry => '1.3.6.1.2.1.16.8.2.1',
  captureBufferControlIndex => '1.3.6.1.2.1.16.8.2.1.1',
  captureBufferIndex => '1.3.6.1.2.1.16.8.2.1.2',
  captureBufferPacketID => '1.3.6.1.2.1.16.8.2.1.3',
  captureBufferPacketData => '1.3.6.1.2.1.16.8.2.1.4',
  captureBufferPacketLength => '1.3.6.1.2.1.16.8.2.1.5',
  captureBufferPacketTime => '1.3.6.1.2.1.16.8.2.1.6',
  captureBufferPacketStatus => '1.3.6.1.2.1.16.8.2.1.7',
  event => '1.3.6.1.2.1.16.9',
  eventTable => '1.3.6.1.2.1.16.9.1',
  eventEntry => '1.3.6.1.2.1.16.9.1.1',
  eventIndex => '1.3.6.1.2.1.16.9.1.1.1',
  eventDescription => '1.3.6.1.2.1.16.9.1.1.2',
  eventType => '1.3.6.1.2.1.16.9.1.1.3',
  eventTypeDefinition => 'RMON-MIB::eventType',
  eventCommunity => '1.3.6.1.2.1.16.9.1.1.4',
  eventLastTimeSent => '1.3.6.1.2.1.16.9.1.1.5',
  eventOwner => '1.3.6.1.2.1.16.9.1.1.6',
  eventStatus => '1.3.6.1.2.1.16.9.1.1.7',
  eventStatusDefinition => 'RMON-MIB::EntryStatus',
  logTable => '1.3.6.1.2.1.16.9.2',
  logEntry => '1.3.6.1.2.1.16.9.2.1',
  logEventIndex => '1.3.6.1.2.1.16.9.2.1.1',
  logIndex => '1.3.6.1.2.1.16.9.2.1.2',
  logTime => '1.3.6.1.2.1.16.9.2.1.3',
  logDescription => '1.3.6.1.2.1.16.9.2.1.4',
  rmonConformance => '1.3.6.1.2.1.16.20',
  rmonMibModule => '1.3.6.1.2.1.16.20.8',
  rmonCompliances => '1.3.6.1.2.1.16.20.9',
  rmonGroups => '1.3.6.1.2.1.16.20.10',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::definitions->{'RMON-MIB'} = {
  channelDataControl => {
    '1' => 'on',
    '2' => 'off',
  },
  alarmSampleType => {
    '1' => 'absoluteValue',
    '2' => 'deltaValue',
  },
  hostTopNRateBase => {
    '1' => 'hostTopNInPkts',
    '2' => 'hostTopNOutPkts',
    '3' => 'hostTopNInOctets',
    '4' => 'hostTopNOutOctets',
    '5' => 'hostTopNOutErrors',
    '6' => 'hostTopNOutBroadcastPkts',
    '7' => 'hostTopNOutMulticastPkts',
  },
  channelEventStatus => {
    '1' => 'eventReady',
    '2' => 'eventFired',
    '3' => 'eventAlwaysReady',
  },
  bufferControlFullAction => {
    '1' => 'lockWhenFull',
    '2' => 'wrapWhenFull',
  },
  bufferControlFullStatus => {
    '1' => 'spaceAvailable',
    '2' => 'full',
  },
  eventType => {
    '1' => 'none',
    '2' => 'log',
    '3' => 'snmptrap',
    '4' => 'logandtrap',
  },
  channelAcceptType => {
    '1' => 'acceptMatched',
    '2' => 'acceptFailed',
  },
  alarmStartupAlarm => {
    '1' => 'risingAlarm',
    '2' => 'fallingAlarm',
    '3' => 'risingOrFallingAlarm',
  },
  EntryStatus => {
    '1' => 'valid',
    '2' => 'createRequest',
    '3' => 'underCreation',
    '4' => 'invalid',
  },
};
