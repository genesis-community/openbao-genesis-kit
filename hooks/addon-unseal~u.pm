package Genesis::Hook::Addon::Openbao::Unseal v1.1.0;

use v5.20;
use warnings; # Genesis min perl version is 5.20

# Only needed for development
BEGIN {push @INC, $ENV{GENESIS_LIB} ? $ENV{GENESIS_LIB} : $ENV{HOME}.'/.genesis/lib'}

use Genesis qw/bail info run read_json_from/;
use Genesis::UI qw/prompt_for_password/;

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
	"Seal keys are taken, in order, from the caller (post-deploy hands over\n".
	"the keys it read before the deploy), from OpenBAO itself, and from the\n".
	"backup copy in the deploying vault. If none of those has them, you will\n".
	"need to provide the unseal keys when prompted.\n";
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

	my $keys = $self->_resolve_seal_keys;

	my @results = map { $self->_unseal_node($_, $keys) } @$nodes;

	my @sealed = grep { !$_->{unsealed} } @results;

	info("");
	info("Unseal summary:");
	info("  " . ($_->{unsealed} ? '#G{+}' : '#R{x}') . " node $_->{index} $_->{short_ip}: $_->{message}")
		for @results;

	# With standby reads forwarded, nothing authenticated works until the
	# unsealed nodes elect a leader, so wait for one whenever a quorum is open.
	my $open = scalar(@results) - scalar(@sealed);
	$self->_wait_for_active_node($nodes) if $open * 2 > scalar(@results);

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

	unless ($self->_may_prompt) {
		info("  #R{x} node $index ($short): no working seal keys, and prompting is disabled");
		return { index => $index, ip => $ip, short_ip => $short, unsealed => 0, message => 'sealed, no keys and no prompting' };
	}

	if ($self->_manual_unseal_node($env, $ip)) {
		info("  #G{+} node $index ($short): unsealed (manual)");
		return { index => $index, ip => $ip, short_ip => $short, unsealed => 1, message => 'unsealed manually' };
	}

	info("  #R{x} node $index ($short): failed to unseal");
	return { index => $index, ip => $ip, short_ip => $short, unsealed => 0, message => 'failed to unseal' };
}
# }}}

# _may_prompt - whether this run may ask the operator for keys {{{
# post-deploy passes allow_prompts, which is false under -y or without a
# terminal, so a deploy never blocks on a prompt. A direct
# `genesis do <env> -- unseal` leaves it unset and may prompt.
sub _may_prompt {
	my ($self) = @_;
	return exists($self->{allow_prompts}) ? ($self->{allow_prompts} ? 1 : 0) : 1;
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
# Reads each key with terminal echo off and submits it straight to the node's
# own sys/unseal endpoint. It never touches the env's safe target, because
# repointing that alias at a sealed peer breaks every later safe call and
# strands the operator without auth. Returns 1 when the node ends up unsealed.
sub _manual_unseal_node {
	my ($self, $env, $ip) = @_;
	my $status = $self->_seal_status($ip);
	unless ($status) {
		info("  #R{x} Could not read seal status from $ip for manual unseal");
		return 0;
	}
	my $threshold = $status->{t} || 3;
	info("  Enter the unseal keys for the node at $ip ($threshold needed, input is hidden):");
	my $attempts = 0;
	while ($attempts < $threshold + 2) {
		my $key = prompt_for_password("  Key: ");
		last if !defined($key) || $key eq '';
		$attempts++;
		my $sealed = $self->_submit_unseal_key($ip, $key);
		if (!defined $sealed) {
			info("  #Y{!} node at $ip rejected that key or did not answer");
			next;
		}
		return 1 unless $sealed;
	}
	my $final = $self->_node_sealed($ip);
	return defined($final) && !$final ? 1 : 0;
}
# }}}

# _seal_status - fetch a node's full seal-status document {{{
sub _seal_status {
	my ($self, $ip) = @_;
	my $curl_opts = $ENV{CURLOPTS} // '';
	my $timeout   = $ENV{TIMEOUT}  // 5;
	my ($out, $rc) = run({ stderr => 0 },
		"curl -Lsk $curl_opts -m$timeout https://$ip/v1/sys/seal-status"
	);
	return undef unless $rc == 0 && $out;
	my $status = eval { JSON::PP::decode_json($out) };
	return ref($status) eq 'HASH' ? $status : undef;
}
# }}}

# _resolve_seal_keys - pick the seal keys to unseal with {{{
# Keys handed over by the caller come first, because they were read before
# the deploy, while the cluster could still answer. OpenBAO's own copy only
# answers once a leader exists, since standby nodes forward reads to the
# active node, so it is useless while every node is sealed. The backup copy
# in the deploying vault is the last automatic source. Returns an arrayref,
# possibly empty, and never logs a value.
sub _resolve_seal_keys {
	my ($self) = @_;

	my $handed = $self->{seal_keys};
	if (ref($handed) eq 'ARRAY' && @$handed) {
		info("Using " . scalar(@$handed) . " seal key(s) handed over by the deploy");
		return $handed;
	}

	my $stored = $self->_load_stored_seal_keys;
	return $stored if @$stored;

	return $self->_load_backup_seal_keys;
}
# }}}

# _load_backup_seal_keys - read the init addon's backup copy of the keys {{{
# The init addon backs the keys up to the deploying vault under this env's
# secrets_base (see _backup_seal_keys_to_provider in addon-init~i.pm). That
# copy lives outside this cluster, so it stays readable while every node is
# sealed. Returns an arrayref of key values ordered key1..keyN, possibly
# empty, and never logs a value.
sub _load_backup_seal_keys {
	my ($self) = @_;

	info("Checking the deploying vault for a backup copy of the seal keys...");

	my $path = eval { $self->env->secrets_base() . 'vault/seal/keys' };
	my $data = $path ? eval { $self->vault->get($path) } : undef;

	unless (ref($data) eq 'HASH' && %$data) {
		info("No backup seal keys found in the deploying vault");
		return [];
	}

	my @names = sort { ($a =~ /(\d+)$/)[0] <=> ($b =~ /(\d+)$/)[0] }
		grep { /^key\d+$/ } keys %$data;
	my @keys = grep { defined($_) && /^[A-Za-z0-9+\/=]+\z/ } map { $data->{$_} } @names;

	if (@keys) {
		info("  #G{+} Found " . scalar(@keys) . " backup seal key(s) at #C{$path}");
	} else {
		info("No usable backup seal keys found at #C{$path}");
	}
	return \@keys;
}
# }}}

# _wait_for_active_node - poll until one node reports itself active {{{
# sys/health is unauthenticated and answers on standbys too (with a non-200
# status), so each node is asked directly. Gives up after OPENBAO_ACTIVE_WAIT
# seconds (default 90) and reports, without failing, because the unseal
# itself has already succeeded. Returns 1 once a node is active, else 0.
sub _wait_for_active_node {
	my ($self, $nodes) = @_;

	my $limit    = $ENV{OPENBAO_ACTIVE_WAIT} // 90;
	my $interval = 3;
	my $waited   = 0;

	info("");
	info("Waiting for the OpenBAO nodes to elect an active node...");
	while (1) {
		for my $node (@$nodes) {
			my $health = $self->_node_health($node->{ip});
			next unless $health && !$health->{sealed} && exists($health->{standby}) && !$health->{standby};
			info("  #G{+} node $node->{index} (" . _short_ip($node->{ip}) . ") is the active node");
			return 1;
		}
		last if $waited >= $limit;
		$self->_pause($interval);
		$waited += $interval;
	}

	info("  #Y{!} No active node after ${limit}s - authenticated calls will fail until one is elected");
	return 0;
}

sub _pause { sleep($_[1]) }
# }}}

# _node_health - fetch a single node's sys/health document {{{
sub _node_health {
	my ($self, $ip) = @_;
	my $curl_opts = $ENV{CURLOPTS} // '';
	my $timeout   = $ENV{TIMEOUT}  // 5;
	my ($out, $rc) = run({ stderr => 0 },
		"curl -sk $curl_opts -m$timeout https://$ip/v1/sys/health"
	);
	return undef unless $rc == 0 && $out;
	my $health = eval { JSON::PP::decode_json($out) };
	return ref($health) eq 'HASH' ? $health : undef;
}
# }}}

# _load_stored_seal_keys - retrieve seal keys stored in OpenBAO, if any {{{
# Reads via the env's existing safe target. Standby nodes forward reads to
# the active node, so this only works once the cluster has a leader.
# Returns an arrayref of key values (possibly empty) - never logs a value.
sub _load_stored_seal_keys {
	my ($self) = @_;
	my $env = $self->env;

	info("Checking for stored seal keys...");

	my ($check_auth, $auth_rc) = run({ stderr => 0 },
		'safe', '-T', $env->name, 'auth', 'status'
	);

	unless ($auth_rc == 0) {
		info("Not authenticated with OpenBAO - its stored seal keys are out of reach");
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

		my ($key_data, $read_rc) = run({ stderr => 0, redact_output => 1 },
			'safe', '-T', $env->name, 'get', $key_path
		);

		if ($read_rc == 0 && $key_data) {
			# `safe get path:key` prints the bare value. Older safe builds printed
			# `key: value`, so accept both shapes before validating the key.
			my $key_value = $key_data;
			$key_value = $1 if $key_value =~ /^\s*key$i\s*:\s*(.+)$/m;
			$key_value =~ s/^\s+|\s+$//g;

			if ($key_value =~ /^[A-Za-z0-9+\/=]+\z/) {
				push @keys, $key_value;
				info("  #G{+} Found seal key $i");
			} else {
				info("  #Y{!} Invalid seal key $i format");
				$errors++;
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
		info("No seal keys could be read from OpenBAO");
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

	# A return inside the eval would only leave the eval, so decide there and
	# return out here.
	my $already_open = $status_rc == 0
		&& eval { !JSON::PP::decode_json($status_out)->{sealed} };
	if ($already_open) {
		info("#G{+ OpenBAO is already unsealed}");
		info("");
		run({ interactive => 1 }, 'safe', '-T', $env->name, 'status');
		return $self->done(1);
	}

	my $keys = $self->_resolve_seal_keys;

	if (@$keys) {
		info("");
		info("Attempting automatic unseal with the seal keys we found...");

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

	unless ($self->_may_prompt) {
		info("#R{x} No seal keys available and prompting is disabled - OpenBAO stays sealed");
		return $self->done(0);
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
