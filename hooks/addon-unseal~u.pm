package Genesis::Hook::Addon::Openbao::Unseal v1.0.0;

use v5.20;
use warnings; # Genesis min perl version is 5.20
use Genesis qw/bail info run read_json_from/;
# Only needed for development
BEGIN {push @INC, $ENV{GENESIS_LIB} ? $ENV{GENESIS_LIB} : $ENV{HOME}.'./.genesis/lib'}

use parent qw(Genesis::Hook::Addon);
use JSON::PP;

sub init {
	my $class = shift;
	my $obj = $class->SUPER::init(@_);
	$obj->check_minimum_genesis_version('3.1.0');
	return $obj;
}

sub cmd_details {
	return
	"Unseal every node of the OpenBAO cluster, making it available for use.\n".
	"Each Raft HA node keeps its own sealed barrier, so every node discovered\n".
	"via BOSH is checked and unsealed independently.\n".
	"If seal keys are stored in OpenBAO, they will be used automatically.\n".
	"Otherwise, you will need to provide the unseal keys when prompted.\n";
}

sub perform {
	my ($self) = @_;
	my $env = $self->env;

	info("");

	my $nodes = $self->_discover_nodes;

	unless ($nodes && @$nodes) {
		info("#Y{!} Could not enumerate OpenBAO nodes via BOSH - falling back to unsealing the single env target.");
		return $self->_unseal_single_target;
	}

	info("Found " . scalar(@$nodes) . " OpenBAO node(s) via BOSH.");
	info("");

	my $keys = $self->_load_stored_seal_keys;

	my @results = map { $self->_unseal_node($_, $keys) } @$nodes;

	my @sealed = grep { !$_->{unsealed} } @results;

	info("");
	info("Unseal summary:");
	info("  " . ($_->{unsealed} ? '#G{+}' : '#R{x}') . " node $_->{index} $_->{short_ip}: $_->{message}")
		for @results;

	info("");
	if (!@sealed) {
		info("#G{+ All OpenBAO nodes are unsealed}");
		return $self->done(1);
	}

	info("#R{x " . scalar(@sealed) . " of " . scalar(@results) . " node(s) remain sealed}");
	return $self->done(0);
}

# _discover_nodes - enumerate OpenBAO instances via BOSH {{{
# Returns an arrayref of {index, ip} hashrefs (index is 0-based, in BOSH's
# reported instance order), or undef if enumeration is not possible (no BOSH
# access, malformed output, or no instances found) so callers can fall back
# gracefully.
sub _discover_nodes {
	my ($self) = @_;

	my ($vms, $rc) = eval { read_json_from($self->env->bosh->execute('vms', '--json')) };
	return undef if $@ || $rc || !$vms;

	my @rows = eval { @{ $vms->{Tables}[0]{Rows} } };
	return undef unless @rows;

	my @nodes;
	for my $row (@rows) {
		my $ip = ref($row->{ips}) eq 'ARRAY' ? $row->{ips}[0] : $row->{ips};
		next unless $ip;
		push @nodes, { index => scalar(@nodes), ip => $ip };
	}

	return @nodes ? \@nodes : undef;
}
# }}}

# _unseal_node - check and, if needed, unseal a single node {{{
# Returns a summary hashref: {index, ip, short_ip, unsealed, message}. Never
# prints or returns an unseal key value - only node identity, seal booleans,
# and progress/outcome text are surfaced.
sub _unseal_node {
	my ($self, $node, $keys) = @_;
	my $env   = $self->env;
	my $index = $node->{index};
	my $ip    = $node->{ip};
	my $short = _short_ip($ip);

	my $sealed = $self->_node_sealed($ip);

	unless (defined $sealed) {
		info("  #R{x} node $index ($short): unreachable");
		return { index => $index, ip => $ip, short_ip => $short, unsealed => 0, message => 'unreachable' };
	}

	unless ($sealed) {
		info("  #G{+} node $index ($short): already unsealed");
		return { index => $index, ip => $ip, short_ip => $short, unsealed => 1, message => 'already unsealed' };
	}

	info("  node $index ($short): sealed, attempting unseal...");

	if ($keys && @$keys) {
		if ($self->_submit_keys_to_node($ip, $keys)) {
			info("  #G{+} node $index ($short): unsealed");
			return { index => $index, ip => $ip, short_ip => $short, unsealed => 1, message => 'unsealed' };
		}
		info("  #Y{!} node $index ($short): automatic unseal failed, falling back to manual entry");
	}

	if ($self->_manual_unseal_node($env, $ip)) {
		info("  #G{+} node $index ($short): unsealed (manual)");
		return { index => $index, ip => $ip, short_ip => $short, unsealed => 1, message => 'unsealed manually' };
	}

	info("  #R{x} node $index ($short): failed to unseal");
	return { index => $index, ip => $ip, short_ip => $short, unsealed => 0, message => 'failed to unseal' };
}
# }}}

# _node_sealed - query a single node's own seal status {{{
# sys/seal-status is unauthenticated, so this hits the node directly and
# never needs (or sends) any secret material. Returns 1 (sealed), 0
# (unsealed), or undef (unreachable / unparsable response).
sub _node_sealed {
	my ($self, $ip) = @_;

	my $curl_opts = $ENV{CURLOPTS} // '';
	my $timeout   = $ENV{TIMEOUT}  // 5;

	my ($out, $rc) = run({ stderr => 0 },
		"curl -Lsk $curl_opts -m$timeout https://$ip/v1/sys/seal-status"
	);
	return undef unless $rc == 0 && $out;

	my $status = eval { JSON::PP::decode_json($out) };
	return undef unless ref($status) eq 'HASH' && exists $status->{sealed};

	return $status->{sealed} ? 1 : 0;
}
# }}}

# _submit_keys_to_node - unseal a single node directly via its own API {{{
# Submits stored keys one at a time to this node's sys/unseal endpoint until
# it reports unsealed or the key list is exhausted. Returns 1/0.
sub _submit_keys_to_node {
	my ($self, $ip, $keys) = @_;

	for my $key (@$keys) {
		my $sealed = $self->_submit_unseal_key($ip, $key);
		return 1 if defined($sealed) && !$sealed;
	}

	my $final = $self->_node_sealed($ip);
	return defined($final) && !$final ? 1 : 0;
}

# _submit_unseal_key - POST a single unseal key to one node {{{
# SECURITY: the key value is written to curl's STDIN as a JSON body
# (`--data-binary @-`) and never appears as a CLI argument, so it cannot show
# up in argv, process listings, or Genesis's command trace log, and it is
# never written to disk. Returns the node's resulting sealed state (1/0), or
# undef if the request failed.
sub _submit_unseal_key {
	my ($self, $ip, $key) = @_;

	my $curl_opts = $ENV{CURLOPTS} // '';
	my $timeout   = $ENV{TIMEOUT}  // 5;
	my $body      = JSON::PP::encode_json({ key => $key });

	my @curl_args = ('curl', '-Lsk');
	push @curl_args, split(' ', $curl_opts) if $curl_opts;
	push @curl_args, ('-m', $timeout, '-X', 'PUT', '--data-binary', '@-', "https://$ip/v1/sys/unseal");

	my ($out, $rc) = run({ stdin => $body, stderr => 0 }, @curl_args);
	return undef unless $rc == 0 && $out;

	my $status = eval { JSON::PP::decode_json($out) };
	return undef unless ref($status) eq 'HASH' && exists $status->{sealed};

	return $status->{sealed} ? 1 : 0;
}
# }}}
# }}}

# _manual_unseal_node - prompt for keys and unseal one node interactively {{{
sub _manual_unseal_node {
	my ($self, $env, $ip) = @_;

	my (undef, $target_rc) = run({ stderr => 0 },
		'safe', 'target', '--no-strongbox', "https://$ip", '-k', $env->name
	);

	unless ($target_rc == 0) {
		info("  #R{x} Could not target node at $ip for manual unseal");
		return 0;
	}

	info("  Please enter the unseal keys for the node at $ip when prompted:");
	run({ interactive => 1 }, 'safe', '-T', $env->name, 'unseal');

	my $sealed = $self->_node_sealed($ip);
	return defined($sealed) && !$sealed ? 1 : 0;
}
# }}}

# _load_stored_seal_keys - retrieve seal keys stored in OpenBAO, if any {{{
# Reads via the env's existing safe target, which only needs to reach one
# reachable/unsealed node (typically the leader) to serve these reads.
# Returns an arrayref of key values (possibly empty) - never logs a value.
sub _load_stored_seal_keys {
	my ($self) = @_;
	my $env = $self->env;

	info("Checking for stored seal keys...");

	my ($check_auth, $auth_rc) = run({ stderr => 0 },
		'safe', '-T', $env->name, 'auth', 'status'
	);

	unless ($auth_rc == 0) {
		info("Not authenticated - will prompt for seal keys manually per node");
		return [];
	}

	my @keys;
	my $errors = 0;

	for (my $i = 1; $i <= 10; $i++) {
		my $key_path = "secret/vault/seal/keys:key$i";

		my (undef, $exists_rc) = run({ stderr => 0 },
			'safe', '-T', $env->name, 'exists', $key_path
		);
		last if $exists_rc != 0;

		my ($key_data, $read_rc) = run({ stderr => 0 },
			'safe', '-T', $env->name, 'get', $key_path
		);

		if ($read_rc == 0 && $key_data) {
			if ($key_data =~ /^[^:]+:(.+)$/m) {
				my $key_value = $1;
				$key_value =~ s/^\s+|\s+$//g;

				if ($key_value =~ /^[A-Za-z0-9+\/=]+$/) {
					push @keys, $key_value;
					info("  #G{+} Found seal key $i");
				} else {
					info("  #Y{!} Invalid seal key $i format");
					$errors++;
				}
			}
		} else {
			info("  #R{x} Failed to read seal key $i");
			$errors++;
		}
	}

	if (@keys) {
		info("");
		info("Found " . scalar(@keys) . " seal keys" . ($errors ? " with $errors errors" : ""));
	} else {
		info("No stored seal keys found - will prompt for keys manually per node");
	}

	return \@keys;
}
# }}}

# _unseal_single_target - legacy whole-cluster unseal, used when BOSH-based {{{
# per-node discovery is unavailable. Reaches only the env's single safe
# target, matching this addon's pre-per-node behavior.
sub _unseal_single_target {
	my ($self) = @_;
	my $env = $self->env;

	my ($status_out, $status_rc) = run({ stderr => 0 },
		'safe', '-T', $env->name, 'vault', 'status', '-format=json'
	);

	if ($status_rc == 0) {
		eval {
			my $status = JSON::PP::decode_json($status_out);
			if (!$status->{sealed}) {
				info("#G{+ OpenBAO is already unsealed}");
				info("");
				run({ interactive => 1 }, 'safe', '-T', $env->name, 'status');
				return $self->done(1);
			}
		};
	}

	my $keys = $self->_load_stored_seal_keys;

	if (@$keys) {
		info("");
		info("Attempting automatic unseal with stored keys...");

		my $keys_content = join("\n", @$keys) . "\n";
		my ($unseal_out, $unseal_rc) = run(
			{ stdin => $keys_content, stderr => 1 },
			'safe', '-T', $env->name, 'unseal'
		);

		if ($unseal_rc == 0) {
			info("#G{+ OpenBAO unsealed successfully!}");
			info("");
			run({ interactive => 1 }, 'safe', '-T', $env->name, 'status');
			return $self->done(1);
		}

		info("#R{x Automatic unseal failed}");
		info("");
		info("Falling back to manual unseal...");
	}

	info("");
	info("Please enter the unseal keys when prompted:");

	run({ interactive => 1 }, 'safe', '-T', $env->name, 'unseal');

	return $self->done();
}
# }}}

# _short_ip - render an IP as its last two octets, e.g. "10.0.20.5" -> ".20.5" {{{
sub _short_ip {
	my ($ip) = @_;
	return $ip unless $ip =~ /^\d+\.\d+\.(\d+\.\d+)$/;
	return ".$1";
}
# }}}

1;
# vim: set ts=2 sw=2 sts=2 noet fdm=marker foldlevel=1:
