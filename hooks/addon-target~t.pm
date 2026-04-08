package Genesis::Hook::Addon::OpenBao::Target v1.0.0;
use v5.20;
use warnings; # Genesis min perl version is 5.20
use Genesis qw/bail info run read_json_from/;
use parent qw(Genesis::Hook::Addon);
sub init {
  my $class = shift;
  my $obj = $class->SUPER::init(@_);
  $obj->check_minimum_genesis_version('3.1.0');
  return $obj;
}

sub cmd_details {
  return
    "Target the OpenBAO cluster and authenticate via a specified auth method (defaults to token), interactively if needed.\n"
  . "Usage: target [METHOD]\n";
}

sub perform {
  my ($self) = @_;
  my $env = $self->env;
  my $env_name = $env->name;

  # Get the authentication method (default to 'token')
  my $method = $self->{args}[0] || 'token';
  info("Using auth method: $method");

  # Resolve openbao_domain or discover OpenBAO IPs
  my $domain = $env->lookup('params.openbao_domain', '');

  if (!$domain) {
    my ($json, $rc) = read_json_from($env->bosh->execute('vms', '--json'));
    bail("Failed to get VM JSON ($rc)") unless $json;

    # collect openbao/* instances
    my @openbao_ips;
    for my $row (@{$json->{Tables}[0]{Rows}}) {
      next unless $row->{instance} =~ /^openbao\//;
      my $ips = $row->{ips};
      push @openbao_ips, ref $ips eq 'ARRAY' ? @$ips : $ips;
    }
    bail("No OpenBAO VMs found") unless @openbao_ips;

    my $timeout = $ENV{TIMEOUT} || 3;
    for my $ip (@openbao_ips) {
      next unless $ip =~ /^\d+\.\d+\.\d+\.\d+$/;
      my (undef, $curl_rc) = run({ stdout=>0, stderr=>0 }, 'curl', '-Lsk', "-m$timeout", "https://$ip");
      if ($curl_rc == 0) {
        $domain = $ip;
        last;
      }
    }
    bail("Could not find a valid OpenBAO IP to connect to.") unless $domain;
  }

  # Target OpenBAO
  my ($t_out, $t_rc) = run({ stderr=>1 }, 'safe', 'target', '--no-strongbox', "https://$domain", '-k', $env_name);
  bail("safe target failed") if $t_rc;

  # Authenticate (interactive if needed)
  my $auth_cmd = "safe -T $env_name auth $method";
  info("Running: $auth_cmd");
  my (undef, $auth_rc) = run({ interactive => 1 }, 'safe', '-T', $env_name, 'auth', $method);
  if ($auth_rc != 0) {
    info("Authentication failed (exit code $auth_rc)");
    return $self->done(0);
  }

  # Verify handshake & status
  my (undef, $h_rc) = run({ stderr=>0 }, 'safe', '-T', $env_name, 'read', 'secret/handshake');
  if ($h_rc == 0) {
    info("OpenBAO is successfully targeted and authenticated.");
    return $self->done(1);
  }

  info("Authentication failed or secret/handshake missing");
  return $self->done(0);
}

1;
# vim: set ts=2 sw=2 sts=2 noet fdm=marker foldlevel=1:
