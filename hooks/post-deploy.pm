package Genesis::Hook::PostDeploy::Openbao v1.2.0;

use v5.20;
use warnings;

# Only needed for development
BEGIN {push @INC, $ENV{GENESIS_LIB} ? $ENV{GENESIS_LIB} : $ENV{HOME}.'/.genesis/lib'}

use parent qw(Genesis::Hook::PostDeploy);

use Genesis qw/info run/;
# Note: Service::Vault is a Genesis framework module for safe CLI interactions.
# It works with OpenBAO unchanged since the APIs are compatible.
use Service::Vault;
use JSON::PP;

# init - Initialize the hook {{{
sub init {
	my ($class, %ops) = @_;
	my $obj = $class->SUPER::init(%ops);
	$obj->check_minimum_genesis_version('3.1.0');
	return $obj;
}
# }}}

# perform - Main hook execution {{{
sub perform {
	my ($self) = @_;

	# Only proceed if deployment was successful
	unless ($ENV{GENESIS_DEPLOY_RC} == 0) {
		info("#R{Deployment failed} - skipping post-deploy actions");
		return $self->done(1);
	}

	info("");
	info("#M{$ENV{GENESIS_ENVIRONMENT}} OpenBAO deployed successfully!");
	info("");

	# Ensure safe target exists for this environment. On fresh deploys
	# the target may not exist yet until BOSH node discovery creates it.
	$self->_ensure_target();

	# Determine vault state via JSON status (exit code is non-zero when
	# sealed or uninitialized, so we parse the output regardless).
	my ($status_out) = run({ stderr => 0 },
		'safe', '-T', $ENV{GENESIS_ENVIRONMENT}, 'vault', 'status', '-format=json'
	);

	if (!$status_out) {
		# Target may be stale (IP changed after delete/redeploy).
		# _auto_init_if_needed will discover nodes via BOSH.
		info("Could not reach OpenBAO at current target");
	} elsif ($status_out =~ /"initialized"\s*:\s*false/) {
		info("OpenBAO is #Y{uninitialized}");
	} elsif ($status_out =~ /"sealed"\s*:\s*true/) {
		info("OpenBAO is currently #Y{sealed} - unsealing is required to access secrets");
		# Every node gets the pre-deploy keys straight through its own
		# sys/unseal. Unsealing only the safe target and then reading the
		# stored keys back through it fails, because a lone unsealed node
		# forwards reads to an active node that does not exist yet.
		my $keys = $self->_predeploy_seal_keys;
		if (@$keys) {
			info("Found unseal keys from pre-deploy, unsealing every node with them...");
		} else {
			info("No pre-deploy seal keys found - looking for the stored and backup copies");
		}
		$self->_show_manual_instructions unless $self->_unseal_all_nodes($keys);
	} else {
		info("OpenBAO is currently #G{unsealed} - checking the remaining Raft nodes");
		$self->_unseal_all_nodes($self->_predeploy_seal_keys);
	}

	# Check if this is the first deployment and auto-initialize if needed
	$self->_auto_init_if_needed();

	# Setup doomsday approle if vault is initialized and unsealed
	$self->_setup_doomsday_approle();

	info(
		"\nFor details about the deployment, run:\n".
		"  #G{genesis info $ENV{GENESIS_ENVIRONMENT}}\n"
	);

	return $self->done(1);
}

sub _show_manual_instructions {
	info(
		"\nUnable to automatically unseal OpenBAO.".
		"\nIf this is a #Y{new deployment}, you need to initialize it first:\n".
		"  #G{genesis do $ENV{GENESIS_ENVIRONMENT} -- init}".
		"\nIf this is an #Y{existing deployment}, you need to unseal it manually:\n".
		"  #G{genesis do $ENV{GENESIS_ENVIRONMENT} -- unseal}\n"
	)
}

# _setup_doomsday_approle - give doomsday read-only credentials in exodus {{{
# The role lives in the deployed OpenBAO, and its credentials are written to
# this environment's exodus data in the deploying vault, where the doomsday
# kit and `genesis lookup --exodus` read them, as the vault kit does.
# Genesis rewrites that exodus data on every deploy, so a fresh secret_id is
# minted each time, and every earlier secret_id of the role is destroyed
# first, so at most one is ever valid.  Every secret goes to safe on stdin.
sub _setup_doomsday_approle {
	my ($self) = @_;
	my $name = $ENV{GENESIS_ENVIRONMENT};

	# Check if vault is initialized and unsealed
	my ($status_out, $status_rc) = run({ stderr => 0 },
		'safe', '-T', $name, 'vault', 'status'
	);

	# Parse status to check if initialized and unsealed
	return unless $status_rc == 0;
	return if $status_out =~ /Initialized\s+false/;
	return if $status_out =~ /Sealed\s+true/;

	# Check if we can authenticate (need to be authenticated to create approles)
	my ($auth_check, $auth_rc) = run({ stderr => 0 },
		'safe', '-T', $name, 'auth', 'status'
	);

	unless ($auth_rc == 0) {
		info("Skipping doomsday approle setup - not authenticated with OpenBAO");
		return;
	}

	my $provider = eval {$self->env->vault};
	unless ($provider) {
		my $err = ($@ || 'no deploying vault is configured for this environment') =~ s/\s+/ /gr;
		info("Skipping doomsday approle setup - could not resolve the deploying vault to store its credentials in: $err");
		return;
	}
	my $exodus_base = $ENV{GENESIS_EXODUS_BASE} // $self->env->exodus_base;
	(my $exodus_path = $exodus_base) =~ s{/+$}{};

	info("");
	info("Setting up doomsday monitoring approle...");

	# Enable approle auth if not already enabled. Retried with a bounded
	# backoff - see _enable_approle_with_retry.
	my ($enable_out, $enable_ok) = $self->_enable_approle_with_retry;

	if ($enable_ok) {
		info("#G{[ok]} AppRole auth enabled");
	} else {
		info("#Y{WARNING:} Could not enable approle auth: $enable_out");
		return;
	}

	# Check if doomsday approle already exists with credentials in exodus
	my ($list_out, $list_rc) = run({ stderr => 0 },
		'safe', '-T', $name, 'vault', 'list', '-format=json', 'auth/approle/role'
	);
	my $roles = $list_rc == 0 && $list_out ? eval {JSON::PP::decode_json($list_out)} : undef;
	if (ref($roles) eq 'ARRAY' && grep {$_ eq 'doomsday'} @$roles) {
		if ($provider->has($exodus_path, 'doomsday_approle_id')
			&& $provider->has($exodus_path, 'doomsday_approle_secret')) {
			info("#G{[ok]} Doomsday approle already exists with credentials in exodus");
			return;
		}
	}

	# Create doomsday read-only policy
	info("Creating doomsday read-only policy...");

	my $policy = <<'EOF';
# Read-only access for doomsday monitoring
path "sys/health" {
	capabilities = ["read"]
}

path "sys/seal-status" {
	capabilities = ["read"]
}

path "sys/host-info" {
	capabilities = ["read"]
}

path "sys/mounts" {
	capabilities = ["read", "list"]
}

path "sys/auth" {
	capabilities = ["read", "list"]
}

# Allow listing all paths to discover what's available
path "*" {
	capabilities = ["list"]
}

# Read-only access to all secrets
path "secret/*" {
	capabilities = ["read", "list"]
}

path "secret/data/*" {
	capabilities = ["read", "list"]
}

path "secret/metadata/*" {
	capabilities = ["read", "list"]
}
EOF

	my (undef, $policy_rc) = run({ stdin => $policy, stderr => '&1' },
		'safe', '-T', $name, 'vault', 'policy', 'write', 'doomsday', '-'
	);

	unless ($policy_rc == 0) {
		info("#R{ERROR:} Failed to create doomsday policy");
		return;
	}
	info("#G{[ok]} Doomsday policy created");

	# Create doomsday approle.  safe set would read the role back and rewrite
	# every field, so the role is written natively.
	info("Creating doomsday approle...");

	my ($create_out, $create_rc) = run({ stderr => '&1' },
		'safe', '-T', $name, 'vault', 'write',
		'auth/approle/role/doomsday',
		'secret_id_ttl=0',
		'token_num_uses=0',
		'token_ttl=1h',
		'token_max_ttl=24h',
		'secret_id_num_uses=0',
		'policies=doomsday'
	);

	unless ($create_rc == 0) {
		info("#R{ERROR:} Failed to create doomsday approle: %s", ($create_out // '') =~ s/\s+/ /gr);
		return;
	}

	# Get role ID
	my ($role_id, $role_rc) = run({ stderr => 0, redact_output => 1 },
		'safe', '-T', $name, 'get', 'auth/approle/role/doomsday/role-id:role_id'
	);
	$role_id = defined($role_id) ? $role_id =~ s/^\s+|\s+$//gr : '';

	unless ($role_rc == 0 && $role_id ne '') {
		info("#R{ERROR:} Failed to get doomsday role ID");
		return;
	}

	# The secret_ids never expire, so destroy every earlier one before
	# minting the next.  The accessors can't authenticate, so they may appear
	# on argv.
	my @accessors = _doomsday_secret_id_accessors($name);
	unless (defined($accessors[0])) {
		info("#R{ERROR:} Failed to list the doomsday approle's secret IDs: %s", $accessors[1]);
		return;
	}
	shift @accessors;
	for my $accessor (@accessors) {
		unless (_destroy_doomsday_secret_id($name, $accessor)) {
			info("#R{ERROR:} Failed to destroy an earlier doomsday secret ID (accessor %s), so no new one was minted", $accessor);
			return;
		}
	}
	info("#G{[ok]} Destroyed %d earlier doomsday secret ID(s)", scalar(@accessors)) if @accessors;

	# Generate secret ID
	my ($secret_out, $secret_rc) = run({ stderr => 0, redact_output => 1 },
		'safe', '-T', $name, 'vault', 'write', '-format=json', '-f', 'auth/approle/role/doomsday/secret-id'
	);
	my $minted = $secret_rc == 0 ? eval {JSON::PP::decode_json($secret_out)} : undef;
	my $data = ref($minted) eq 'HASH' && ref($minted->{data}) eq 'HASH' ? $minted->{data} : {};
	my ($secret_id, $secret_accessor) = @{$data}{qw/secret_id secret_id_accessor/};

	unless (length($secret_id // '') && length($secret_accessor // '')) {
		info("#R{ERROR:} Failed to generate doomsday secret ID");
		return;
	}

	# Store in exodus, each secret through stdin
	info("Storing doomsday approle credentials in exodus...");

	my ($id_rc, $id_err) = _set_secret_on_stdin($provider, $exodus_path, 'doomsday_approle_id', $role_id);
	my ($store_rc, $store_err) = $id_rc == 0
		? _set_secret_on_stdin($provider, $exodus_path, 'doomsday_approle_secret', $secret_id,
			"doomsday_approle_secret_accessor=$secret_accessor")
		: ($id_rc, $id_err);

	if ($store_rc == 0) {
		info("#G{#\@{+} Doomsday approle created successfully!}");
		info("  Credentials stored in exodus at: #C{%s} in the deploying vault #M{%s}", $exodus_path, $provider->url // '');
		info("  - doomsday_approle_id");
		info("  - doomsday_approle_secret");
		info("  - doomsday_approle_secret_accessor");
	} else {
		$store_err =~ s/\s+/ /g;
		info("#R{ERROR:} Failed to store doomsday credentials in exodus: %s", $store_err || "safe exited $store_rc");
		# Nobody holds the new secret ID, so don't leave it valid
		if (_destroy_doomsday_secret_id($name, $secret_accessor)) {
			info("  Destroyed the doomsday secret ID that could not be stored");
		} else {
			info("  #Y{WARNING:} Could not destroy the doomsday secret ID that could not be stored (accessor %s)", $secret_accessor);
		}
	}
}
# }}}

# _set_secret_on_stdin - write one secret value to a provider through stdin {{{
# Extra key=value pairs, which must not be secret, go in the same write.
# Returns the exit code and the error text.
sub _set_secret_on_stdin {
	my ($provider, $path, $key, $value, @pairs) = @_;
	my (undef, $rc, $err) = $provider->query(
		{stdin => $value, stderr => 0, redact_output => 1},
		'set', $path, "$key\@-", @pairs
	);
	return ($rc, $err // '');
}
# }}}

# _doomsday_secret_id_accessors - accessors of every doomsday secret_id {{{
# Returns (1, @accessors), or (undef, $error) when they can't be listed.
# OpenBAO answers a list with nothing in it with "No value found".
sub _doomsday_secret_id_accessors {
	my ($name) = @_;
	my ($out, $rc, $err) = run({ stderr => 0 },
		'safe', '-T', $name, 'vault', 'list', '-format=json', 'auth/approle/role/doomsday/secret-id'
	);
	my $text = join(' ', grep {defined} $out, $err);
	return (1) if $rc != 0 && $text =~ /No value found/i;
	my $list = $rc == 0 ? eval {JSON::PP::decode_json($out)} : undef;
	return (1, grep {defined && !ref && /\S/} @$list) if ref($list) eq 'ARRAY';
	$text =~ s/\s+/ /g;
	return (undef, $text =~ /\S/ ? $text : "safe exited $rc");
}
# }}}

# _destroy_doomsday_secret_id - destroy one secret_id by its accessor {{{
sub _destroy_doomsday_secret_id {
	my ($name, $accessor) = @_;
	my (undef, $rc) = run({ stderr => 0 },
		'safe', '-T', $name, 'vault', 'write', 'auth/approle/role/doomsday/secret-id-accessor/destroy',
		"secret_id_accessor=$accessor"
	);
	return $rc == 0;
}
# }}}

# _enable_approle_with_retry - enable approle auth with a bounded readiness gate {{{
# Immediately after a fresh deploy, `auth status` can already succeed while
# the bloc-vault is still settling underneath it (e.g. Raft leader election
# not yet complete), so `vault auth enable approle` can fail transiently
# even though a retry moments later would succeed (seen on drgao). Retry
# with a short backoff capped at ~30s total before giving up; this remains
# non-fatal either way, same as before.
sub _enable_approle_with_retry {
	my ($self) = @_;

	my @backoff = (2, 4, 8, 16); # seconds between attempts; sums to ~30s
	my $enable_out = '';

	for (my $attempt = 0; ; $attempt++) {
		# stderr is merged so that the "already in use" answer, which exits
		# non-zero, is seen.  The arguments go to safe as they are, so no
		# shell redirect belongs among them.
		($enable_out) = run({ stderr => '&1' },
			'safe', '-T', $ENV{GENESIS_ENVIRONMENT}, 'vault', 'auth', 'enable', 'approle'
		);
		$enable_out //= '';

		return ($enable_out, 1)
			if $enable_out =~ /Success\! Enabled approle auth method/ || $enable_out =~ /path is already in use/;

		last if $attempt >= @backoff;

		my $wait = $backoff[$attempt];
		info("  #Y{!} AppRole auth not ready yet, retrying in ${wait}s...");
		$self->_backoff_sleep($wait);
	}

	return ($enable_out, 0);
}
# }}}

sub _backoff_sleep {
	my ($self, $seconds) = @_;
	sleep($seconds);
}

sub _ensure_target {
	my ($self) = @_;

	# Check if the target already works (exit code 2 is fine — means
	# sealed/uninitialized but reachable; no output means unreachable)
	my ($check_out) = run({ stderr => 0 },
		'safe', '-T', $ENV{GENESIS_ENVIRONMENT}, 'vault', 'status', '-format=json'
	);
	return if $check_out;

	# Discover OpenBAO VMs via BOSH and create the safe target
	my ($bosh_out, $bosh_rc) = run({ stderr => 0 },
		'bosh', '-e', $self->env->bosh->alias, '-d', $self->env->bosh->deployment,
		'vms', '--json'
	);
	return unless $bosh_rc == 0 && $bosh_out;

	eval {
		my $data = JSON::PP::decode_json($bosh_out);
		my @ips = map {$_->{ips}} @{$data->{Tables}[0]{Rows}};

		foreach my $ip (@ips) {
			my (undef, $target_rc) = run({ stderr => 0 },
				'safe', 'target', '--no-strongbox', "https://$ip", '-k', $ENV{GENESIS_ENVIRONMENT}
			);
			last if $target_rc == 0;
		}
	};
}

sub _auto_init_if_needed {
	my ($self) = @_;

	# Check if vault is initialized (target is already established by _ensure_target)
	my ($status_out, $status_rc) = run({ stderr => 0 },
		'safe', '-T', $ENV{GENESIS_ENVIRONMENT}, 'vault', 'status'
	);

	# Parse status to check if initialized
	if ($status_out =~ /Initialized\s+false/) {
		info("");
		info("Detected #Y{uninitialized OpenBAO} - running automatic initialization...");

		# Load and run the init addon
		require $self->{kit}->path('hooks/addon-init~i.pm');
		my $init_hook = Genesis::Hook::Addon::Openbao::Init->init(
			kit => $self->{kit},
			env => $self->{env},
			script => 'init',
			args => []
		);

		my $init_rc = $init_hook->perform();

		if ($init_rc) {
			info("#G{#@{+} OpenBAO initialized successfully!}");

			# The init addon stores seal keys, so we should be able to unseal now
			my ($check_out, $check_rc) = run({ stderr => 0 },
				'safe', '-T', $ENV{GENESIS_ENVIRONMENT}, 'exists', 'secret/vault/seal/keys'
			);

			if ($check_rc == 0) {
				info("");
				info("Attempting to unseal the newly initialized OpenBAO...");

				# Get seal keys and unseal
				my @keys;
				for (my $i = 1; $i <= 5; $i++) {
					my ($key_out, $key_rc) = run({ stderr => 0, redact_output => 1 },
						'safe', '-T', $ENV{GENESIS_ENVIRONMENT}, 'get', "secret/vault/seal/keys:key$i"
					);
					if ($key_rc == 0 && $key_out) {
						chomp($key_out);
						push @keys, $key_out;
					}
				}

				if (@keys) {
					my $keys_content = join("\n", @keys);
					my ($unseal_out, $unseal_rc) = run(
						{ stdin => $keys_content, stderr => 1 },
						'safe', '-T', $ENV{GENESIS_ENVIRONMENT}, 'unseal'
					);

					if ($unseal_rc == 0) {
						info("#G{#@{+} OpenBAO unsealed successfully!}");
						$self->_unseal_all_nodes(\@keys);
					} else {
						info("#Y{WARNING:} Failed to unseal OpenBAO automatically");
						info("You can unseal manually with: #G{genesis do $ENV{GENESIS_ENVIRONMENT} -- unseal}");
					}
				}
			}
		} else {
			info("#R{ERROR:} Automatic initialization failed");
			info("You can initialize manually with: #G{genesis do $ENV{GENESIS_ENVIRONMENT} -- init}");
		}
	}
}
# }}}

# _predeploy_seal_keys - the seal keys the pre-deploy hook saved {{{
# pre-deploy writes one key per line to GENESIS_PREDEPLOY_DATAFILE. Returns
# an arrayref of the well-formed keys, possibly empty, and never logs a value.
sub _predeploy_seal_keys {
	my ($self) = @_;
	my $file = $ENV{GENESIS_PREDEPLOY_DATAFILE};
	return [] unless $file && -s $file;
	open(my $fh, '<', $file) or return [];
	my @keys = grep { /^[A-Za-z0-9+\/=]+\z/ } map { s/^\s+|\s+$//gr } <$fh>;
	close($fh);
	return \@keys;
}
# }}}

# _unseal_all_nodes - run the unseal addon so every Raft node is unsealed {{{
# The safe target only reaches one node, and each Raft HA node keeps its own
# sealed barrier, so a fresh deploy or a rolling update leaves the peers sealed
# even when the targeted node is open. The unseal addon enumerates the nodes
# through BOSH and unseals each one through its own API, using the keys
# handed in here when there are any. Failure is reported, never fatal.
# Returns 1 when every node ends up unsealed, else 0.
sub _unseal_all_nodes {
	my ($self, $keys) = @_;
	my $ok = eval {
		require $self->{kit}->path('hooks/addon-unseal~u.pm');
		my $unseal_hook = Genesis::Hook::Addon::Openbao::Unseal->init(
			kit => $self->{kit},
			env => $self->{env},
			script => 'unseal',
			args => [],
			seal_keys => $keys // [],
			allow_prompts => $self->{interactive} ? 1 : 0,
		);
		$unseal_hook->perform();
	};
	if ($@) {
		info("#Y{WARNING:} Could not verify the remaining OpenBAO nodes: $@");
		info("You can unseal them with: #G{genesis do $ENV{GENESIS_ENVIRONMENT} -- unseal}");
		return 0;
	}
	return $ok ? 1 : 0;
}
# }}}

1;

# vim: set ts=2 sw=2 sts=2 noet fdm=marker foldlevel=1:
