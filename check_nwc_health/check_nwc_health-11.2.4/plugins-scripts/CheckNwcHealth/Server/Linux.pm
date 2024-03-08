package CheckNwcHealth::Server::Linux;
our @ISA = qw(CheckNwcHealth::Device);
use strict;

sub init {
  my ($self) = @_;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("CheckNwcHealth::Server::Linux::Component::EnvironmentalSubsystem")
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("CheckNwcHealth::Server::Linux::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::disk::usage/) {
    $self->analyze_and_check_disk_subsystem("CheckNwcHealth::UCDMIB::Component::DiskSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("CheckNwcHealth::Server::Linux::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::process::status/) {
    $self->analyze_and_check_process_subsystem("CheckNwcHealth::UCDMIB::Component::ProcessSubsystem");
  } elsif ($self->mode =~ /device::uptime/ && $self->implements_mib("HOST-RESOURCES-MIB")) {
    $self->analyze_and_check_uptime_subsystem("CheckNwcHealth::HOSTRESOURCESMIB::Component::UptimeSubsystem");
  } else {
    $self->no_such_mode();
  }
}

