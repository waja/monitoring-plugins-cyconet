package Monitoring::GLPlugin::SNMP::MibsAndOids::CISCOLICENSEMGMTMIB;

$Monitoring::GLPlugin::SNMP::MibsAndOids::origin->{'CISCO-LICENSE-MGMT-MIB'} = {
  url => '',
  name => 'CISCO-LICENSE-MGMT-MIB',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::mib_ids->{'CISCO-LICENSE-MGMT-MIB'} =
  '1.3.6.1.4.1.9.9.543';

$Monitoring::GLPlugin::SNMP::MibsAndOids::mibs_and_oids->{'CISCO-LICENSE-MGMT-MIB'} = {
  'ciscoLicenseMgmtMIB' => '1.3.6.1.4.1.9.9.543',
  'ciscoLicenseMgmtMIBNotifs' => '1.3.6.1.4.1.9.9.543.0',
  'ciscoLicenseMgmtMIBObjects' => '1.3.6.1.4.1.9.9.543.1',
  'clmgmtLicenseConfiguration' => '1.3.6.1.4.1.9.9.543.1.1',
  'clmgmtNextFreeLicenseActionIndex' => '1.3.6.1.4.1.9.9.543.1.1.1',
  'clmgmtLicenseActionTable' => '1.3.6.1.4.1.9.9.543.1.1.2',
  'clmgmtLicenseActionEntry' => '1.3.6.1.4.1.9.9.543.1.1.2.1',
  'clmgmtLicenseActionIndex' => '1.3.6.1.4.1.9.9.543.1.1.2.1.1',
  'clmgmtLicenseActionEntPhysicalIndex' => '1.3.6.1.4.1.9.9.543.1.1.2.1.2',
  'clmgmtLicenseActionTransferProtocol' => '1.3.6.1.4.1.9.9.543.1.1.2.1.3',
  'clmgmtLicenseActionTransferProtocolDefinition' => 'CISCO-LICENSE-MGMT-MIB::ClmgmtLicenseTransferProtocol',
  'clmgmtLicenseServerAddressType' => '1.3.6.1.4.1.9.9.543.1.1.2.1.4',
  'clmgmtLicenseServerAddress' => '1.3.6.1.4.1.9.9.543.1.1.2.1.5',
  'clmgmtLicenseServerUsername' => '1.3.6.1.4.1.9.9.543.1.1.2.1.6',
  'clmgmtLicenseServerPassword' => '1.3.6.1.4.1.9.9.543.1.1.2.1.7',
  'clmgmtLicenseFile' => '1.3.6.1.4.1.9.9.543.1.1.2.1.8',
  'clmgmtLicenseStore' => '1.3.6.1.4.1.9.9.543.1.1.2.1.9',
  'clmgmtLicenseActionLicenseIndex' => '1.3.6.1.4.1.9.9.543.1.1.2.1.10',
  'clmgmtLicensePermissionTicketFile' => '1.3.6.1.4.1.9.9.543.1.1.2.1.11',
  'clmgmtLicenseRehostTicketFile' => '1.3.6.1.4.1.9.9.543.1.1.2.1.12',
  'clmgmtLicenseBackupFile' => '1.3.6.1.4.1.9.9.543.1.1.2.1.13',
  'clmgmtLicenseStopOnFailure' => '1.3.6.1.4.1.9.9.543.1.1.2.1.14',
  'clmgmtLicenseAction' => '1.3.6.1.4.1.9.9.543.1.1.2.1.15',
  'clmgmtLicenseActionDefinition' => 'CISCO-LICENSE-MGMT-MIB::clmgmtLicenseAction',
  'clmgmtLicenseActionState' => '1.3.6.1.4.1.9.9.543.1.1.2.1.16',
  'clmgmtLicenseActionStateDefinition' => 'CISCO-LICENSE-MGMT-MIB::ClmgmtLicenseActionState',
  'clmgmtLicenseJobQPosition' => '1.3.6.1.4.1.9.9.543.1.1.2.1.17',
  'clmgmtLicenseActionFailCause' => '1.3.6.1.4.1.9.9.543.1.1.2.1.18',
  'clmgmtLicenseActionFailCauseDefinition' => 'CISCO-LICENSE-MGMT-MIB::ClmgmtLicenseActionFailCause',
  'clmgmtLicenseActionStorageType' => '1.3.6.1.4.1.9.9.543.1.1.2.1.19',
  'clmgmtLicenseActionRowStatus' => '1.3.6.1.4.1.9.9.543.1.1.2.1.20',
  'clmgmtLicenseAcceptEULA' => '1.3.6.1.4.1.9.9.543.1.1.2.1.21',
  'clmgmtLicenseEULAFile' => '1.3.6.1.4.1.9.9.543.1.1.2.1.22',
  'clmgmtLicenseActionResultTable' => '1.3.6.1.4.1.9.9.543.1.1.3',
  'clmgmtLicenseActionResultEntry' => '1.3.6.1.4.1.9.9.543.1.1.3.1',
  'clmgmtLicenseNumber' => '1.3.6.1.4.1.9.9.543.1.1.3.1.1',
  'clmgmtLicenseIndivActionState' => '1.3.6.1.4.1.9.9.543.1.1.3.1.2',
  'clmgmtLicenseIndivActionStateDefinition' => 'CISCO-LICENSE-MGMT-MIB::ClmgmtLicenseActionState',
  'clmgmtLicenseIndivActionFailCause' => '1.3.6.1.4.1.9.9.543.1.1.3.1.3',
  'clmgmtLicenseIndivActionFailCauseDefinition' => 'CISCO-LICENSE-MGMT-MIB::ClmgmtLicenseActionFailCause',
  'clmgmtLicenseInformation' => '1.3.6.1.4.1.9.9.543.1.2',
  'clmgmtLicenseStoreInfoTable' => '1.3.6.1.4.1.9.9.543.1.2.1',
  'clmgmtLicenseStoreInfoEntry' => '1.3.6.1.4.1.9.9.543.1.2.1.1',
  'clmgmtLicenseStoreIndex' => '1.3.6.1.4.1.9.9.543.1.2.1.1.1',
  'clmgmtLicenseStoreName' => '1.3.6.1.4.1.9.9.543.1.2.1.1.2',
  'clmgmtLicenseStoreTotalSize' => '1.3.6.1.4.1.9.9.543.1.2.1.1.3',
  'clmgmtLicenseStoreSizeRemaining' => '1.3.6.1.4.1.9.9.543.1.2.1.1.4',
  'clmgmtLicenseDeviceInfoTable' => '1.3.6.1.4.1.9.9.543.1.2.2',
  'clmgmtLicenseDeviceInfoEntry' => '1.3.6.1.4.1.9.9.543.1.2.2.1',
  'clmgmtDefaultLicenseStore' => '1.3.6.1.4.1.9.9.543.1.2.2.1.1',
  'clmgmtLicenseInfoTable' => '1.3.6.1.4.1.9.9.543.1.2.3',
  'clmgmtLicenseInfoEntry' => '1.3.6.1.4.1.9.9.543.1.2.3.1',
  'clmgmtLicenseStoreUsed' => '1.3.6.1.4.1.9.9.543.1.2.3.1.1',
  'clmgmtLicenseIndex' => '1.3.6.1.4.1.9.9.543.1.2.3.1.2',
  'clmgmtLicenseFeatureName' => '1.3.6.1.4.1.9.9.543.1.2.3.1.3',
  'clmgmtLicenseFeatureVersion' => '1.3.6.1.4.1.9.9.543.1.2.3.1.4',
  'clmgmtLicenseType' => '1.3.6.1.4.1.9.9.543.1.2.3.1.5',
  'clmgmtLicenseTypeDefinition' => 'CISCO-LICENSE-MGMT-MIB::clmgmtLicenseType',
  'clmgmtLicenseCounted' => '1.3.6.1.4.1.9.9.543.1.2.3.1.6',
  'clmgmtLicenseValidityPeriod' => '1.3.6.1.4.1.9.9.543.1.2.3.1.7',
  'clmgmtLicenseValidityPeriodRemaining' => '1.3.6.1.4.1.9.9.543.1.2.3.1.8',
  'clmgmtLicenseExpiredPeriod' => '1.3.6.1.4.1.9.9.543.1.2.3.1.9',
  'clmgmtLicenseMaxUsageCount' => '1.3.6.1.4.1.9.9.543.1.2.3.1.10',
  'clmgmtLicenseUsageCountRemaining' => '1.3.6.1.4.1.9.9.543.1.2.3.1.11',
  'clmgmtLicenseEULAStatus' => '1.3.6.1.4.1.9.9.543.1.2.3.1.12',
  'clmgmtLicenseComments' => '1.3.6.1.4.1.9.9.543.1.2.3.1.13',
  'clmgmtLicenseStatus' => '1.3.6.1.4.1.9.9.543.1.2.3.1.14',
  'clmgmtLicenseStatusDefinition' => 'CISCO-LICENSE-MGMT-MIB::clmgmtLicenseStatus',
  'clmgmtLicenseStartDate' => '1.3.6.1.4.1.9.9.543.1.2.3.1.15',
  'clmgmtLicenseEndDate' => '1.3.6.1.4.1.9.9.543.1.2.3.1.16',
  'clmgmtLicensePeriodUsed' => '1.3.6.1.4.1.9.9.543.1.2.3.1.17',
  'clmgmtLicensableFeatureTable' => '1.3.6.1.4.1.9.9.543.1.2.4',
  'clmgmtLicensableFeatureEntry' => '1.3.6.1.4.1.9.9.543.1.2.4.1',
  'clmgmtFeatureIndex' => '1.3.6.1.4.1.9.9.543.1.2.4.1.1',
  'clmgmtFeatureName' => '1.3.6.1.4.1.9.9.543.1.2.4.1.2',
  'clmgmtFeatureVersion' => '1.3.6.1.4.1.9.9.543.1.2.4.1.3',
  'clmgmtFeatureValidityPeriodRemaining' => '1.3.6.1.4.1.9.9.543.1.2.4.1.4',
  'clmgmtFeatureWhatIsCounted' => '1.3.6.1.4.1.9.9.543.1.2.4.1.5',
  'clmgmtFeatureStartDate' => '1.3.6.1.4.1.9.9.543.1.2.4.1.6',
  'clmgmtFeatureEndDate' => '1.3.6.1.4.1.9.9.543.1.2.4.1.7',
  'clmgmtFeaturePeriodUsed' => '1.3.6.1.4.1.9.9.543.1.2.4.1.8',
  'clmgmtLicenseDeviceInformation' => '1.3.6.1.4.1.9.9.543.1.3',
  'clmgmtNextFreeDevCredExportActionIndex' => '1.3.6.1.4.1.9.9.543.1.3.1',
  'clmgmtDevCredExportActionTable' => '1.3.6.1.4.1.9.9.543.1.3.2',
  'clmgmtDevCredExportActionEntry' => '1.3.6.1.4.1.9.9.543.1.3.2.1',
  'clmgmtDevCredExportActionIndex' => '1.3.6.1.4.1.9.9.543.1.3.2.1.1',
  'clmgmtDevCredEntPhysicalIndex' => '1.3.6.1.4.1.9.9.543.1.3.2.1.2',
  'clmgmtDevCredTransferProtocol' => '1.3.6.1.4.1.9.9.543.1.3.2.1.3',
  'clmgmtDevCredTransferProtocolDefinition' => 'CISCO-LICENSE-MGMT-MIB::ClmgmtLicenseTransferProtocol',
  'clmgmtDevCredServerAddressType' => '1.3.6.1.4.1.9.9.543.1.3.2.1.4',
  'clmgmtDevCredServerAddress' => '1.3.6.1.4.1.9.9.543.1.3.2.1.5',
  'clmgmtDevCredServerUsername' => '1.3.6.1.4.1.9.9.543.1.3.2.1.6',
  'clmgmtDevCredServerPassword' => '1.3.6.1.4.1.9.9.543.1.3.2.1.7',
  'clmgmtDevCredExportFile' => '1.3.6.1.4.1.9.9.543.1.3.2.1.8',
  'clmgmtDevCredCommand' => '1.3.6.1.4.1.9.9.543.1.3.2.1.9',
  'clmgmtDevCredCommandDefinition' => 'CISCO-LICENSE-MGMT-MIB::clmgmtDevCredCommand',
  'clmgmtDevCredCommandState' => '1.3.6.1.4.1.9.9.543.1.3.2.1.10',
  'clmgmtDevCredCommandStateDefinition' => 'CISCO-LICENSE-MGMT-MIB::ClmgmtLicenseActionState',
  'clmgmtDevCredCommandFailCause' => '1.3.6.1.4.1.9.9.543.1.3.2.1.11',
  'clmgmtDevCredCommandFailCauseDefinition' => 'CISCO-LICENSE-MGMT-MIB::clmgmtDevCredCommandFailCause',
  'clmgmtDevCredStorageType' => '1.3.6.1.4.1.9.9.543.1.3.2.1.12',
  'clmgmtDevCredRowStatus' => '1.3.6.1.4.1.9.9.543.1.3.2.1.13',
  'clmgmtLicenseNotifObjects' => '1.3.6.1.4.1.9.9.543.1.4',
  'clmgmtLicenseUsageNotifEnable' => '1.3.6.1.4.1.9.9.543.1.4.1',
  'clmgmtLicenseDeploymentNotifEnable' => '1.3.6.1.4.1.9.9.543.1.4.2',
  'clmgmtLicenseErrorNotifEnable' => '1.3.6.1.4.1.9.9.543.1.4.3',
  'ciscoLicenseMgmtMIBConform' => '1.3.6.1.4.1.9.9.543.2',
  'ciscoLicenseMgmtCompliances' => '1.3.6.1.4.1.9.9.543.2.1',
  'ciscoLicenseMgmtGroups' => '1.3.6.1.4.1.9.9.543.2.2',
};

$Monitoring::GLPlugin::SNMP::MibsAndOids::definitions->{'CISCO-LICENSE-MGMT-MIB'} = {
  'ClmgmtLicenseActionFailCause' => {
    '1' => 'none',
    '2' => 'generalFailure',
    '3' => 'transferProtocolNotSupported',
    '4' => 'fileServerNotReachable',
    '5' => 'unrecognizedEntPhysicalIndex',
    '6' => 'invalidLicenseFilePath',
    '7' => 'invalidLicenseFile',
    '8' => 'invalidLicenseLine',
    '9' => 'licenseAlreadyExists',
    '10' => 'licenseNotValidForDevice',
    '11' => 'invalidLicenseCount',
    '12' => 'invalidLicensePeriod',
    '13' => 'licenseInUse',
    '14' => 'invalidLicenseStore',
    '15' => 'licenseStorageFull',
    '16' => 'invalidPermissionTicketFile',
    '17' => 'invalidPermissionTicket',
    '18' => 'invalidRehostTicketFile',
    '19' => 'invalidRehostTicket',
    '20' => 'invalidLicenseBackupFile',
    '21' => 'licenseClearInProgress',
    '22' => 'invalidLicenseEULAFile',
  },
  'ClmgmtLicenseTransferProtocol' => {
    '1' => 'none',
    '2' => 'local',
    '3' => 'tftp',
    '4' => 'ftp',
    '5' => 'rcp',
    '6' => 'http',
    '7' => 'scp',
    '8' => 'sftp',
  },
  'clmgmtDevCredCommand' => {
    '1' => 'noOp',
    '2' => 'getDeviceCredentials',
  },
  'clmgmtDevCredCommandFailCause' => {
    '1' => 'none',
    '2' => 'unknownError',
    '3' => 'transferProtocolNotSupported',
    '4' => 'fileServerNotReachable',
    '5' => 'unrecognizedEntPhysicalIndex',
    '6' => 'invalidFile',
  },
  'clmgmtLicenseAction' => {
    '1' => 'noOp',
    '2' => 'install',
    '3' => 'clear',
    '4' => 'processPermissionTicket',
    '5' => 'regenerateLastRehostTicket',
    '6' => 'backup',
    '7' => 'generateEULA',
  },
  'clmgmtLicenseType' => {
    '1' => 'demo',
    '2' => 'extension',
    '3' => 'gracePeriod',
    '4' => 'permanent',
    '5' => 'paidSubscription',
    '6' => 'evaluationSubscription',
    '7' => 'extensionSubscription',
    '8' => 'evalRightToUse',
    '9' => 'rightToUse',
    '10' => 'permanentRightToUse',
  },
  'clmgmtLicenseStatus' => {
    '1' => 'inactive',
    '2' => 'notInUse',
    '3' => 'inUse',
    '4' => 'expiredInUse',
    '5' => 'expiredNotInUse',
    '6' => 'usageCountConsumed',
  },
  'ClmgmtLicenseActionState' => {
    '1' => 'none',
    '2' => 'pending',
    '3' => 'inProgress',
    '4' => 'successful',
    '5' => 'partiallySuccessful',
    '6' => 'failed',
  },
};