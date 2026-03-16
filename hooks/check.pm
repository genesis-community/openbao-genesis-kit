package Genesis::Hook::Check::OpenBao v1.0.0;

use v5.20;
use warnings;

BEGIN {push @INC, $ENV{GENESIS_LIB} ? $ENV{GENESIS_LIB} : $ENV{HOME}.'/.genesis/lib'}

use parent qw(Genesis::Hook::Check);

use Genesis qw/info/;

sub init {
  my ($class, %ops) = @_;
  my $obj = $class->SUPER::init(%ops);
  $obj->check_minimum_genesis_version('3.1.0');
  return $obj;
}

sub perform {
  my ($self) = @_;
  my $ok = 1;

  # Cloud Config checks
  if ($ENV{GENESIS_CLOUD_CONFIG}) {
    $self->start_check("Checking cloud config");

    my @errors;
    # TODO: Requires newer Genesis API (missing_cloud_config_keys)
    #push @errors, $self->env->missing_cloud_config_keys(
    #  vm_type   => [$self->env->lookup('params.openbao_vm_type',   'default')],
    #  network   => [$self->env->lookup('params.openbao_network',   'openbao')],
    #  disk_type => [$self->env->lookup('params.openbao_disk_type', 'default')]
    #);

    if (@errors) {
      $self->check_result(0, join("\n", @errors));
      $ok = 0;
    } else {
      $self->check_result(1);
    }
  }

  return $self->done($ok);
}

1;
