package CheckNwcHealth::Fortigate::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my ($self) = @_;
  $self->get_snmp_objects('FORTINET-FORTIGATE-MIB', (qw(
      fgSysMemUsage)));
}

sub check {
  my ($self) = @_;
  $self->add_info('checking memory');
  if (defined $self->{fgSysMemUsage}) {
    $self->add_info(sprintf 'memory usage is %.2f%%',
        $self->{fgSysMemUsage});
    $self->set_thresholds(warning => 80, critical => 90);
    $self->add_message($self->check_thresholds($self->{fgSysMemUsage}));
    $self->add_perfdata(
        label => 'memory_usage',
        value => $self->{fgSysMemUsage},
        uom => '%',
    );
  } else {
    $self->add_unknown('cannot aquire memory usage');
  }
}

