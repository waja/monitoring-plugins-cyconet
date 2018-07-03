package Classes::Cisco::CISCOIPSECFLOWMONITOR::Component::VpnSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my ($self) = @_;
  $self->get_snmp_tables('CISCO-IPSEC-FLOW-MONITOR-MIB', [
      ['ciketunnels', 'cikeTunnelTable', 'Classes::Cisco::CISCOIPSECFLOWMONITOR::Component::VpnSubsystem::CikeTunnel',  sub { my ($o) = @_; $o->{parent} = $self; $self->filter_name($o->{cikeTunRemoteValue})}],
  ]);
}

sub check {
  my ($self) = @_;
  if (! @{$self->{ciketunnels}}) {
    $self->add_critical(sprintf 'tunnel to %s does not exist',
        $self->opts->name);
  } else {
    foreach (@{$self->{ciketunnels}}) {
      $_->check();
    }
  }
}


package Classes::Cisco::CISCOIPSECFLOWMONITOR::Component::VpnSubsystem::CikeTunnel;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my ($self) = @_;
# cikeTunRemoteValue per --name angegeben, muss active sein
# ansonsten watch-vpns, delta tunnels ueberwachen
  $self->add_info(sprintf 'tunnel to %s is %s',
      $self->{cikeTunRemoteValue}, $self->{cikeTunStatus});
  if ($self->{cikeTunStatus} ne 'active') {
    $self->add_critical();
  } else {
    $self->add_ok();
  }
}

