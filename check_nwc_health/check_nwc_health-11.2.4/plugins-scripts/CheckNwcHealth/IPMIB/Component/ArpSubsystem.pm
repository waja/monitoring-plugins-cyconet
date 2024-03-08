package CheckNwcHealth::IPMIB::Component::ArpSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my ($self) = @_;
  $self->{interfaces} = [];
  $self->get_snmp_tables('IP-MIB', [
      ['oentries', 'ipNetToMediaTable', 'CheckNwcHealth::IPMIB::Component::ArpSubsystem::Entry'],
      ['entries', 'ipNetToPhysicalTable', 'CheckNwcHealth::IPMIB::Component::ArpSubsystem::Entry'],
  ]);
}

sub check {
  my ($self) = @_;
  $self->add_info('checking the arp cache');
  if ($self->mode =~ /device::arp::list/) {
    printf "found %d entries in the ARP cache\n", scalar(@{$self->{oentries}});
    if ($self->opts->report eq "json") {
      printf "[\n";
      printf "%s\n", join(", ", map {
        $_->list();
      } @{$self->{oentries}});
      printf "]\n";
    } else {
      foreach (@{$self->{oentries}}) {
        $_->list();
      }
      $self->add_ok("have fun");
    }
  }
}


package CheckNwcHealth::IPMIB::Component::ArpSubsystem::Entry;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);

sub finish {
  my ($self) = @_;
  $self->{ipNetToMediaPhysAddress} = $self->unhex_mac($self->{ipNetToMediaPhysAddress});
}

sub list {
  my ($self) = @_;
  if ($self->opts->report eq "json") {
    return sprintf '{"%s": "%s"}', $self->{ipNetToMediaNetAddress}, $self->{ipNetToMediaPhysAddress};
  } else {
    printf "%-20s %s\n", $self->{ipNetToMediaNetAddress}, $self->{ipNetToMediaPhysAddress};
  }
}

