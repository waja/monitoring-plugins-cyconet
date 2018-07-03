package Classes::OSPF::Component::NeighborSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my ($self) = @_;
  $self->get_snmp_tables('OSPF-MIB', [
    ['nbr', 'ospfNbrTable', 'Classes::OSPF::Component::NeighborSubsystem::Neighbor', , sub { my ($o) = @_; return $self->filter_name($o->{ospfNbrIpAddr}) && $self->filter_name2($o->{ospfNbrRtrId}) }],
  ]);
  if ($self->establish_snmp_secondary_session()) {
    $self->clear_table_cache('OSPF-MIB', 'ospfNbrTable');
    $self->get_snmp_tables('OSPF-MIB', [
      ['nbr', 'ospfNbrTable', 'Classes::OSPF::Component::NeighborSubsystem::Neighbor', , sub { my ($o) = @_; return $self->filter_name($o->{ospfNbrIpAddr}) && $self->filter_name2($o->{ospfNbrRtrId}) }],
    ]);
  }
  if (! @{$self->{nbr}}) {
    $self->add_unknown("no neighbors found");
  }
}

sub check {
  my ($self) = @_;
  if ($self->mode =~ /device::ospf::neighbor::list/) {
    foreach (@{$self->{nbr}}) {
      printf "%s %s %s\n", $_->{name}, $_->{ospfNbrRtrId}, $_->{ospfNbrState};
    }
    $self->add_ok("have fun");
  } else {
    map { $_->check(); } @{$self->{nbr}};
  }
}

package Classes::OSPF::Component::NeighborSubsystem::Neighbor;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
# Index: ospfNbrIpAddr, ospfNbrAddressLessIndex

sub finish {
  my ($self) = @_;
  $self->{name} = $self->{ospfNbrIpAddr} || $self->{ospfNbrAddressLessIndex}
}

sub check {
  my ($self) = @_;
  $self->add_info(sprintf "neighbor %s (Id %s) has status %s",
      $self->{name}, $self->{ospfNbrRtrId}, $self->{ospfNbrState});
  if ($self->{ospfNbrState} ne "full" && $self->{ospfNbrState} ne "twoWay") {
    $self->add_critical();
  } else {
    $self->add_ok();
  }
}

# eventuell: warning, wenn sich die RouterId ändert
