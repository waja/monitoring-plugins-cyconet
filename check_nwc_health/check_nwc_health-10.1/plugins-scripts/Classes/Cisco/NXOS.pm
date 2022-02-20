package Classes::Cisco::NXOS;
our @ISA = qw(Classes::Cisco);
use strict;

sub init {
  my ($self) = @_;
  if ($self->mode =~ /device::hardware::health/) {
    #$self->mult_snmp_max_msg_size(10);
    $self->analyze_and_check_environmental_subsystem("Classes::Cisco::NXOS::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::cisco::fex::watch/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Cisco::NXOS::Component::FexSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Cisco::IOS::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Cisco::NXOS::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::config/) {
    $self->analyze_and_check_config_subsystem("Classes::Cisco::IOS::Component::ConfigSubsystem");
  } elsif ($self->mode =~ /device::hsrp/) {
    $self->analyze_and_check_hsrp_subsystem("Classes::HSRP::Component::HSRPSubsystem");
  } else {
    $self->no_such_mode();
  }
}

sub pretty_sysdesc {
  my ($self, $sysDescr) = @_;
  if ($sysDescr =~ /(Cisco NX-OS.*? n\d+),.*(Version .*), RELEASE SOFTWARE/) {
    return $1.' '.$2;
  }
}
