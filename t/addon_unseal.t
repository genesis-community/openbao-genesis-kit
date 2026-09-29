#!/usr/bin/env perl
# Unit-level coverage for hooks/addon-unseal~u.pm.
#
# The unseal addon used to run `safe -T <env> unseal` against the single env
# target, which only reaches one node (typically the leader). In a 3-voter
# Raft HA cluster each node keeps its own sealed barrier, so after a rolling
# redeploy the other nodes stay sealed. This drives the per-node discovery,
# per-node seal-status check, and per-node unseal helpers directly against a
# minimal mock $self, mirroring t/addon_init.t and t/post_deploy_init_class.t.
#
# It also asserts the hard security constraint from the addon's own
# comments: an unseal key VALUE must never appear as a `run()` argv element -
# it may only travel via the `stdin` option (a real pipe, never a file).
#
# Requires the real genesis Perl library on GENESIS_LIB or ~/.genesis/lib,
# same as the hook itself expects (see its "Only needed for development"
# BEGIN block).

use v5.20;
use warnings;
use FindBin;
use Test::More;
use JSON::PP;

require "$FindBin::Bin/../hooks/addon-unseal~u.pm";

# perform() waits for an active node after unsealing; keep that wait from
# polling in suites that do not stub sys/health.
$ENV{OPENBAO_ACTIVE_WAIT} = 0;

# --- minimal mocks -----------------------------------------------------------

package MockBosh;
sub new { my ($c, %a) = @_; bless {%a}, $c }
sub execute {
	my ($self, @cmd) = @_;
	return $self->{on_execute}->(@cmd) if $self->{on_execute};
	return ( undef, 1, 'no on_execute stub configured' );
}

package MockEnv;
sub new { my ($c, %a) = @_; bless {%a}, $c }
sub name { $_[0]->{name} }
sub bosh { $_[0]->{bosh} }
sub secrets_base { '/secret/lab/openbao/' }

package MockVault;
sub new { my ($c, %a) = @_; bless {%a}, $c }
sub get {
	my ($self, $path) = @_;
	push @{ $self->{reads} }, $path;
	die "vault unreachable\n" if $self->{fail};
	return $self->{data} // {};
}

package main;

sub build_self {
	my (%opts) = @_;
	my $env = MockEnv->new(
		name => $opts{name} // 'lab-openbao',
		bosh => $opts{bosh} // MockBosh->new,
	);
	return bless {
		env_obj   => $env,
		vault_obj => $opts{vault} // MockVault->new,
		( exists $opts{seal_keys} ? ( seal_keys => $opts{seal_keys} ) : () ),
	}, 'Genesis::Hook::Addon::Openbao::Unseal';
}

{
	no strict 'refs';
	no warnings 'redefine', 'once';
	*Genesis::Hook::Addon::Openbao::Unseal::env   = sub { $_[0]->{env_obj} };
	*Genesis::Hook::Addon::Openbao::Unseal::vault = sub { $_[0]->{vault_obj} };
}

# Installs a `run()` stub that records every call (opts + args separately, so
# tests can assert on argv without being fooled by stdin content), and
# dispatches to a caller-supplied responder keyed off the joined args.
sub install_run {
	my ($responder) = @_;
	my @calls;
	no strict 'refs';
	no warnings 'redefine', 'once';
	*Genesis::Hook::Addon::Openbao::Unseal::run = sub {
		my $opts = ( ref( $_[0] ) eq 'HASH' ) ? shift : {};
		my @args = @_;
		my $cmd  = join( ' ', @args );
		push @calls, { opts => $opts, args => [@args], cmd => $cmd };
		return $responder->( $cmd, $opts, @args );
	};
	return \@calls;
}

# --- _short_ip ----------------------------------------------------------------

subtest '_short_ip renders the last two octets' => sub {
	is( Genesis::Hook::Addon::Openbao::Unseal::_short_ip('10.0.20.5'), '.20.5', 'formats a normal IPv4' );
	is( Genesis::Hook::Addon::Openbao::Unseal::_short_ip('not-an-ip'), 'not-an-ip', 'passes through non-IPv4 unchanged' );
};

# --- _discover_nodes -----------------------------------------------------------

subtest '_discover_nodes enumerates instances via BOSH' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	local *Genesis::Hook::Addon::Openbao::Unseal::read_json_from = sub {
		return (
			{
				Tables => [
					{
						Rows => [
							{ ips => '10.0.20.5' },
							{ ips => '10.0.24.5' },
							{ ips => '10.0.28.5' },
						]
					}
				]
			},
			0
		);
	};

	my $self  = build_self();
	my $nodes = $self->_discover_nodes;

	is( scalar @$nodes, 3, 'discovers all three nodes' );
	is_deeply(
		$nodes,
		[ { index => 0, ip => '10.0.20.5' }, { index => 1, ip => '10.0.24.5' }, { index => 2, ip => '10.0.28.5' } ],
		'indexes nodes 0-based in BOSH row order'
	);
};

subtest '_discover_nodes returns undef when BOSH is unavailable' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	local *Genesis::Hook::Addon::Openbao::Unseal::read_json_from = sub { return ( undef, 1 ) };

	my $self = build_self();
	is( $self->_discover_nodes, undef, 'reports no nodes rather than dying' );
};

subtest '_discover_nodes returns undef when there are no rows' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	local *Genesis::Hook::Addon::Openbao::Unseal::read_json_from = sub {
		return ( { Tables => [ { Rows => [] } ] }, 0 );
	};

	my $self = build_self();
	is( $self->_discover_nodes, undef, 'treats an empty instance list as unavailable' );
};

# --- _node_sealed ---------------------------------------------------------------

subtest '_node_sealed parses seal-status responses' => sub {
	my $self = build_self();

	my $calls = install_run( sub {
		my ($cmd) = @_;
		return ( '{"sealed":true}', 0 )  if $cmd =~ /10\.0\.20\.5/;
		return ( '{"sealed":false}', 0 ) if $cmd =~ /10\.0\.24\.5/;
		return ( '', 7 )                 if $cmd =~ /10\.0\.28\.5/;    # unreachable
		return ( 'not json', 0 )         if $cmd =~ /10\.0\.32\.5/;    # malformed
		return ( '', 0 );
	} );

	is( $self->_node_sealed('10.0.20.5'), 1,     'reports sealed true' );
	is( $self->_node_sealed('10.0.24.5'), 0,     'reports sealed false' );
	is( $self->_node_sealed('10.0.28.5'), undef, 'reports undef when unreachable' );
	is( $self->_node_sealed('10.0.32.5'), undef, 'reports undef on unparsable response' );

	ok( ( grep { $_->{cmd} =~ m{sys/seal-status} } @$calls ), 'hits the node-local seal-status endpoint' );
};

# --- _submit_unseal_key: the hard security constraint ---------------------------

subtest '_submit_unseal_key never puts the key value in argv - only in stdin' => sub {
	my $self      = build_self();
	my $secret_key = 'TOTALLY-SECRET-UNSEAL-KEY-VALUE';

	my $calls = install_run( sub {
		my ( $cmd, $opts ) = @_;
		return ( '{"sealed":false}', 0 ) if $cmd =~ m{sys/unseal};
		return ( '', 1 );
	} );

	my $result = $self->_submit_unseal_key( '10.0.20.5', $secret_key );
	is( $result, 0, 'reports the node as unsealed after the key is accepted' );

	is( scalar @$calls, 1, 'made exactly one run() call' );

	for my $call (@$calls) {
		for my $arg ( @{ $call->{args} } ) {
			unlike( $arg, qr/\Q$secret_key\E/, "argv element '$arg' does not contain the key value" );
		}
		unlike( $call->{cmd}, qr/\Q$secret_key\E/, 'joined argv does not contain the key value' );
	}

	like( $calls->[0]{opts}{stdin}, qr/\Q$secret_key\E/, 'the key value travels only via the stdin option' );
	ok( ( grep { $_ eq '--data-binary' } @{ $calls->[0]{args} } ), 'posts the stdin body via --data-binary @-' );
	ok( ( grep { $_ eq '@-' } @{ $calls->[0]{args} } ), 'reads the POST body from stdin, not a file' );
};

subtest '_submit_unseal_key reports undef on request failure' => sub {
	my $self = build_self();
	install_run( sub { return ( '', 22 ) } );

	is( $self->_submit_unseal_key( '10.0.20.5', 'some-key' ), undef, 'undef on non-zero exit' );
};

# --- _submit_keys_to_node --------------------------------------------------------

subtest '_submit_keys_to_node stops once the node reports unsealed' => sub {
	my $self = build_self();

	my $calls = install_run( sub {
		my ($cmd) = @_;
		return ( '{"sealed":true}',  0 ) if $cmd =~ m{sys/unseal};    # every submitted key still sealed until 3rd
		return ( '{"sealed":false}', 0 ) if $cmd =~ m{sys/seal-status};
		return ( '', 0 );
	} );

	# Override just the unseal submission to unseal on key 3, so we can prove
	# the loop stops early rather than submitting all keys regardless.
	my $submit_calls = 0;
	no strict 'refs';
	no warnings 'redefine', 'once';
	local *Genesis::Hook::Addon::Openbao::Unseal::_submit_unseal_key = sub {
		my ( $self, $ip, $key ) = @_;
		$submit_calls++;
		return $submit_calls >= 3 ? 0 : 1;    # sealed until the 3rd key
	};

	my $keys = [ 'key-one', 'key-two', 'key-three', 'key-four', 'key-five' ];
	my $ok   = $self->_submit_keys_to_node( '10.0.20.5', $keys );

	is( $ok, 1, 'reports success' );
	is( $submit_calls, 3, 'stops submitting keys as soon as the node unseals' );
};

subtest '_submit_keys_to_node reports failure when keys are exhausted' => sub {
	my $self = build_self();

	install_run( sub {
		my ($cmd) = @_;
		return ( '{"sealed":true}', 0 ) if $cmd =~ m{sys/seal-status};
		return ( '', 0 );
	} );

	no strict 'refs';
	no warnings 'redefine', 'once';
	local *Genesis::Hook::Addon::Openbao::Unseal::_submit_unseal_key = sub { return 1 };    # always still sealed

	is( $self->_submit_keys_to_node( '10.0.20.5', [ 'k1', 'k2' ] ), 0, 'reports failure' );
};

# --- _manual_unseal_node ---------------------------------------------------------

subtest '_manual_unseal_node prompts and submits keys to the node itself' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	my $self    = build_self();
	my $sealed  = 1;
	my @prompts = ( 'TYPEDKEYONE', 'TYPEDKEYTWO' );
	my $asked   = 0;
	local *Genesis::Hook::Addon::Openbao::Unseal::prompt_for_password = sub { $asked++; shift @prompts };

	my $calls = install_run( sub {
		my ( $cmd, $opts ) = @_;
		return ( JSON::PP::encode_json( { sealed => JSON::PP::true, t => 2 } ), 0 ) if $cmd =~ m{sys/seal-status};
		if ( $cmd =~ m{https://10\.0\.20\.5/v1/sys/unseal} ) {
			$sealed = 0 if $opts->{stdin} =~ /TYPEDKEYTWO/;
			return ( JSON::PP::encode_json( { sealed => $sealed ? JSON::PP::true : JSON::PP::false } ), 0 );
		}
		return ( '', 1 );
	} );

	is( $self->_manual_unseal_node( $self->env, '10.0.20.5' ), 1, 'reports success once the node reports unsealed' );
	is( $asked, 2, 'prompts once per key until the node opens' );
	ok( !( grep { $_->{cmd} =~ /safe/ } @$calls ), 'never touches the safe target' );
	ok( !( grep { $_->{cmd} =~ /TYPEDKEY/ } @$calls ), 'typed keys never appear in argv' );
};

subtest '_manual_unseal_node reports failure when the node cannot be read' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	my $asked = 0;
	local *Genesis::Hook::Addon::Openbao::Unseal::prompt_for_password = sub { $asked++; '' };
	my $self = build_self();
	install_run( sub { return ( '', 1 ) } );    # seal-status unreachable

	is( $self->_manual_unseal_node( $self->env, '10.0.20.5' ), 0, 'reports failure' );
	is( $asked, 0, 'never prompts' );
};

# --- _unseal_node: per-node orchestration ----------------------------------------

subtest '_unseal_node skips an already-unsealed node' => sub {
	my $self = build_self();
	install_run( sub { return ( '{"sealed":false}', 0 ) } );

	my $result = $self->_unseal_node( { index => 1, ip => '10.0.24.5' }, [] );

	is( $result->{unsealed}, 1,                    'reports unsealed' );
	is( $result->{message},  'already unsealed', 'is idempotent - no unseal attempted' );
};

subtest '_unseal_node falls back to manual prompt when no stored keys are available' => sub {
	my $self = build_self();

	# _node_sealed and _manual_unseal_node are stubbed directly below, so
	# no run() calls are expected on this path - not even installing a
	# run() stub proves that.
	no strict 'refs';
	no warnings 'redefine', 'once';
	my $manual_called = 0;
	local *Genesis::Hook::Addon::Openbao::Unseal::_node_sealed = sub {
		my ( $self, $ip ) = @_;
		return $manual_called ? 0 : 1;
	};
	local *Genesis::Hook::Addon::Openbao::Unseal::_manual_unseal_node = sub {
		$manual_called++;
		return 1;
	};

	my $result = $self->_unseal_node( { index => 2, ip => '10.0.28.5' }, [] );

	is( $manual_called, 1,              'invoked the manual fallback' );
	is( $result->{unsealed}, 1,         'reports unsealed' );
	is( $result->{message},  'unsealed manually', 'labels the result as manual' );
};

# --- perform(): full multi-node integration --------------------------------------

subtest 'perform unseals every sealed node and leaves unsealed nodes alone' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';

	local *Genesis::Hook::Addon::Openbao::Unseal::read_json_from = sub {
		return (
			{
				Tables => [
					{
						Rows => [
							{ ips => '10.0.20.5' },    # already unsealed
							{ ips => '10.0.24.5' },    # sealed, unsealed via stored keys
							{ ips => '10.0.28.5' },    # sealed, unsealed via stored keys
						]
					}
				]
			},
			0
		);
	};

	# Format must satisfy the addon's own key validation (base64/hex-like,
	# no punctuation - see _load_stored_seal_keys), so use alphanumeric
	# placeholders here rather than the FAKE-UNSEAL-KEY-N style used
	# elsewhere in this file.
	my $secret_key_1 = 'FAKEUNSEALKEYVALUEONE';
	my $secret_key_2 = 'FAKEUNSEALKEYVALUETWO';
	my $secret_key_3 = 'FAKEUNSEALKEYVALUETHREE';
	my @secret_keys  = ( $secret_key_1, $secret_key_2, $secret_key_3 );

	my %sealed = ( '10.0.20.5' => 0, '10.0.24.5' => 1, '10.0.28.5' => 1 );

	my $calls = install_run( sub {
		my ( $cmd, $opts, @args ) = @_;

		return ( '', 0 ) if $cmd =~ /safe -T \S+ auth status/;

		if ( $cmd =~ /safe -T \S+ exists secret\/vault\/seal\/keys:key(\d+)/ ) {
			return ( '', $1 <= 3 ? 0 : 1 );
		}
		if ( $cmd =~ /safe -T \S+ get secret\/vault\/seal\/keys:key(\d+)/ ) {
			my $n = $1;
			return ( "key$n: " . $secret_keys[ $n - 1 ], 0 ) if $n <= 3;
			return ( '', 1 );
		}

		if ( $cmd =~ m{https://([\d.]+)/v1/sys/seal-status} ) {
			my $ip = $1;
			return ( JSON::PP::encode_json( { sealed => ( $sealed{$ip} ? JSON::PP::true : JSON::PP::false ) } ), 0 );
		}

		if ( $cmd =~ m{https://([\d.]+)/v1/sys/unseal} ) {
			my $ip = $1;
			$sealed{$ip} = 0;    # a single stored key is enough to unseal in this fixture
			return ( JSON::PP::encode_json( { sealed => JSON::PP::false } ), 0 );
		}

		return ( '', 0 );
	} );

	my $self   = build_self();
	my $result = $self->perform;

	is( $result, 1, 'perform reports success once every node is unsealed' );
	is( $self->completed, 1, 'hook marks itself complete' );

	is( $sealed{'10.0.24.5'}, 0, 'node 1 ends up unsealed' );
	is( $sealed{'10.0.28.5'}, 0, 'node 2 ends up unsealed' );

	for my $secret ( $secret_key_1, $secret_key_2, $secret_key_3 ) {
		for my $call (@$calls) {
			for my $arg ( @{ $call->{args} } ) {
				unlike( $arg, qr/\Q$secret\E/, "argv element never carries a stored key value ($arg)" );
			}
		}
	}
};

subtest 'perform falls back to the single-target path when BOSH discovery fails' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';

	local *Genesis::Hook::Addon::Openbao::Unseal::read_json_from = sub { return ( undef, 1 ) };

	my $fallback_called = 0;
	local *Genesis::Hook::Addon::Openbao::Unseal::_unseal_single_target = sub {
		$fallback_called++;
		return $_[0]->done(1);
	};

	my $self   = build_self();
	my $result = $self->perform;

	is( $fallback_called, 1, 'falls back to the legacy single-target path' );
	is( $result, 1, 'propagates the fallback result' );
};

# --- prompting is off when post-deploy runs non-interactively ------------------------

subtest '_unseal_node never prompts when prompting is disabled' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	my $manual = 0;
	local *Genesis::Hook::Addon::Openbao::Unseal::_manual_unseal_node = sub { $manual++; 1 };
	install_run( sub { return ( JSON::PP::encode_json( { sealed => JSON::PP::true } ), 0 ) } );

	my $self = build_self();
	$self->{allow_prompts} = 0;
	my $result = $self->_unseal_node( { index => 0, ip => '10.0.20.5' }, [] );

	is( $manual, 0, 'skips the manual prompt' );
	is( $result->{unsealed}, 0, 'reports the node as still sealed' );
};

subtest '_unseal_single_target stops when the target is already unsealed' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	my $resolved = 0;
	local *Genesis::Hook::Addon::Openbao::Unseal::_resolve_seal_keys = sub { $resolved++; [] };
	my $calls = install_run( sub {
		my ($cmd) = @_;
		return ( '{"sealed": false}', 0 ) if $cmd =~ /vault status -format=json/;
		return ( '', 0 );
	} );

	my $self = build_self();
	is( $self->_unseal_single_target, 1, 'reports success' );
	is( $resolved, 0, 'never looks for keys' );
	ok( !( grep { $_->{cmd} =~ /safe -T \S+ unseal/ } @$calls ), 'never runs safe unseal again' );
};

subtest '_unseal_single_target reports failure instead of prompting when prompting is disabled' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	local *Genesis::Hook::Addon::Openbao::Unseal::_resolve_seal_keys = sub { [] };
	my $calls = install_run( sub {
		my ($cmd) = @_;
		return ( '{"sealed": true}', 2 ) if $cmd =~ /vault status -format=json/;
		return ( '', 0 );
	} );

	my $self = build_self();
	$self->{allow_prompts} = 0;
	is( $self->_unseal_single_target, 0, 'reports failure' );
	ok( !( grep { $_->{opts}{interactive} } @$calls ), 'never runs anything interactively' );
};

subtest 'stored seal key reads are redacted from the trace' => sub {
	my $calls = install_run( sub {
		my ($cmd) = @_;
		return ( '', 0 ) if $cmd =~ /auth status/;
		return ( '', $cmd =~ /key1$/ ? 0 : 1 ) if $cmd =~ / exists /;
		return ( 'STOREDKEYONE', 0 ) if $cmd =~ / get /;
		return ( '', 1 );
	} );

	my $self = build_self();
	is_deeply( $self->_load_stored_seal_keys, ['STOREDKEYONE'], 'reads the stored key' );
	my @gets = grep { $_->{cmd} =~ / get / } @$calls;
	ok( @gets && !( grep { !$_->{opts}{redact_output} } @gets ), 'every get asks run() to redact its output' );
};

# --- seal key resolution ----------------------------------------------------------

subtest '_resolve_seal_keys prefers keys handed over by the deploy' => sub {
	my $vault = MockVault->new( data => { key1 => 'BACKUPKEY' } );
	my $self  = build_self( seal_keys => [ 'HANDEDKEYONE', 'HANDEDKEYTWO' ], vault => $vault );
	my $calls = install_run( sub { return ( '', 0 ) } );

	is_deeply( $self->_resolve_seal_keys, [ 'HANDEDKEYONE', 'HANDEDKEYTWO' ], 'returns the handed keys' );
	is( scalar @$calls, 0, 'never asks the cluster' );
	ok( !$vault->{reads}, 'never reads the backup copy' );
};

subtest '_resolve_seal_keys falls back to the deploying vault backup' => sub {
	my $vault = MockVault->new(
		data => {
			key2       => 'BACKUPKEYTWO',
			key10      => 'BACKUPKEYTEN',
			key1       => 'BACKUPKEYONE',
			root_token => 'NOTANUNSEALKEY',
		}
	);
	my $self = build_self( vault => $vault );
	install_run( sub {
		my ($cmd) = @_;
		return ( '', 1 ) if $cmd =~ /safe -T \S+ auth status/;    # no leader, no auth
		return ( '', 0 );
	} );

	is_deeply(
		$self->_resolve_seal_keys,
		[ 'BACKUPKEYONE', 'BACKUPKEYTWO', 'BACKUPKEYTEN' ],
		'returns the backup keys in key-number order and skips non-key fields'
	);
	is_deeply( $vault->{reads}, ['/secret/lab/openbao/vault/seal/keys'], 'reads the backup under secrets_base' );
};

subtest '_resolve_seal_keys returns nothing when every source is empty' => sub {
	my $self = build_self( vault => MockVault->new( fail => 1 ) );
	install_run( sub { return ( '', 1 ) } );

	is_deeply( $self->_resolve_seal_keys, [], 'returns an empty list without dying' );
};

# --- waiting for an active node -----------------------------------------------------

subtest '_wait_for_active_node returns once a node reports itself active' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	local $ENV{OPENBAO_ACTIVE_WAIT} = 30;
	my @pauses;
	local *Genesis::Hook::Addon::Openbao::Unseal::_pause = sub { push @pauses, $_[1] };

	my $polls = 0;
	install_run( sub {
		my ($cmd) = @_;
		return ( '', 1 ) unless $cmd =~ m{https://([\d.]+)/v1/sys/health};
		my $ip = $1;
		$polls++;
		my $active = $ip eq '10.0.24.5' && @pauses >= 2;
		return ( JSON::PP::encode_json( { sealed => JSON::PP::false, standby => $active ? JSON::PP::false : JSON::PP::true } ), 0 );
	} );

	my $self  = build_self();
	my $nodes = [ { index => 0, ip => '10.0.20.5' }, { index => 1, ip => '10.0.24.5' } ];
	is( $self->_wait_for_active_node($nodes), 1, 'reports an active node' );
	is( scalar @pauses, 2, 'kept polling until the election finished' );
};

subtest '_wait_for_active_node gives up after the limit' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	local $ENV{OPENBAO_ACTIVE_WAIT} = 6;
	my @pauses;
	local *Genesis::Hook::Addon::Openbao::Unseal::_pause = sub { push @pauses, $_[1] };
	install_run( sub { return ( JSON::PP::encode_json( { sealed => JSON::PP::false, standby => JSON::PP::true } ), 0 ) } );

	my $self = build_self();
	is( $self->_wait_for_active_node( [ { index => 0, ip => '10.0.20.5' } ] ), 0, 'reports no active node' );
	is_deeply( \@pauses, [ 3, 3 ], 'stopped after the configured limit' );
};

# --- perform(): the post-deploy case with every node sealed --------------------------

subtest 'perform unseals a fully sealed cluster with handed keys and no cluster reads' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	local $ENV{OPENBAO_ACTIVE_WAIT} = 3;
	local *Genesis::Hook::Addon::Openbao::Unseal::_pause = sub { };
	local *Genesis::Hook::Addon::Openbao::Unseal::read_json_from = sub {
		return ( { Tables => [ { Rows => [ { ips => '10.0.20.5' }, { ips => '10.0.24.5' }, { ips => '10.0.28.5' } ] } ] }, 0 );
	};

	my %sealed = ( '10.0.20.5' => 1, '10.0.24.5' => 1, '10.0.28.5' => 1 );
	my $calls  = install_run( sub {
		my ($cmd) = @_;
		if ( $cmd =~ m{https://([\d.]+)/v1/sys/seal-status} ) {
			return ( JSON::PP::encode_json( { sealed => $sealed{$1} ? JSON::PP::true : JSON::PP::false } ), 0 );
		}
		if ( $cmd =~ m{https://([\d.]+)/v1/sys/unseal} ) {
			$sealed{$1} = 0;
			return ( JSON::PP::encode_json( { sealed => JSON::PP::false } ), 0 );
		}
		if ( $cmd =~ m{https://([\d.]+)/v1/sys/health} ) {
			return ( JSON::PP::encode_json( { sealed => JSON::PP::false, standby => $1 eq '10.0.20.5' ? JSON::PP::false : JSON::PP::true } ), 0 );
		}
		return ( '', 1 );    # any safe call would fail: no leader yet
	} );

	my $self   = build_self( seal_keys => [ 'HANDEDKEYONE', 'HANDEDKEYTWO', 'HANDEDKEYTHREE' ] );
	my $result = $self->perform;

	is( $result, 1, 'every node ends up unsealed' );
	is_deeply( [ sort values %sealed ], [ 0, 0, 0 ], 'all three nodes opened' );
	ok( !( grep { $_->{cmd} =~ /^safe / } @$calls ), 'never reads keys back through the cluster' );
	ok( ( grep { $_->{cmd} =~ m{sys/health} } @$calls ), 'waited for an active node' );
};

done_testing;
