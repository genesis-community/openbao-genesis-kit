#!/usr/bin/env perl
# Unit-level coverage for Genesis::Hook::Addon::Openbao::Init::_backup_seal_keys_to_provider.
#
# hooks/addon-init~i.pm stores the freshly-generated seal quorum inside the
# OpenBAO cluster that quorum unseals (_store_seal_keys), which is circular:
# if that cluster seals, the keys needed to unseal it are behind the seal.
# _backup_seal_keys_to_provider writes a second, non-circular copy into the
# deploying vault for this environment. This bypasses the full `perform`
# flow (BOSH VM discovery, curl connectivity, real `safe` calls) and calls
# the sub directly against a minimal mock $self, mirroring t/service_routes.t
# in the cf kit.
#
# Requires the real genesis Perl library on GENESIS_LIB or ~/.genesis/lib,
# same as hooks/addon-init~i.pm itself expects (see its "Only needed for
# development" BEGIN block).

use v5.20;
use warnings;
use FindBin;
use Test::More;

require "$FindBin::Bin/../hooks/addon-init~i.pm";

# --- minimal mocks -----------------------------------------------------------

package MockEnv;
sub new { my ($c, %a) = @_; bless {%a}, $c }
sub secrets_base { $_[0]->{secrets_base} }

package MockVaultProvider;
sub new { my ($c, %a) = @_; bless { set_path_calls => [], %a }, $c }
sub url { $_[0]->{url} }
sub set_path {
	my ( $s, $path, $data ) = @_;
	die "$s->{set_path_error}\n" if $s->{set_path_error};
	push @{ $s->{set_path_calls} }, { path => $path, data => $data };
	return 1;
}

package main;

sub build_self {
	my (%opts) = @_;

	my $env = MockEnv->new( secrets_base => $opts{secrets_base} // 'secret/ocfp/lab/openbao/' );
	my $vault_provider = $opts{vault_provider};    # may be undef, to exercise the "no deploying vault" path
	my $vault_error    = $opts{vault_error};

	return bless {
		env_obj      => $env,
		vault_obj    => $vault_provider,
		vault_error  => $vault_error,
	}, 'Genesis::Hook::Addon::Openbao::Init';
}

{
	no strict 'refs';
	no warnings 'redefine', 'once';
	*Genesis::Hook::Addon::Openbao::Init::env = sub { $_[0]->{env_obj} };
	*Genesis::Hook::Addon::Openbao::Init::vault = sub {
		my $self = shift;
		die $self->{vault_error} . "\n" if $self->{vault_error};
		return $self->{vault_obj};
	};
}

# --- backs up to a genuinely different deploying provider --------------------

subtest 'backs up seal keys to the deploying vault' => sub {
	my $provider = MockVaultProvider->new( url => 'https://10.0.0.5:8200' );
	my $self     = build_self( vault_provider => $provider, secrets_base => 'secret/ocfp/lab/openbao/' );

	my @seal_keys = ( 'FAKE-UNSEAL-KEY-1', 'FAKE-UNSEAL-KEY-2', 'FAKE-UNSEAL-KEY-3' );
	my $result = $self->_backup_seal_keys_to_provider( \@seal_keys, 'https://10.0.1.7:8200' );

	is( $result, 1, 'reports success' );
	is( scalar @{ $provider->{set_path_calls} }, 1, 'writes exactly once' );
	is( $provider->{set_path_calls}[0]{path}, 'secret/ocfp/lab/openbao/vault/seal/keys',
		'writes under the env secrets_base, using the vault/seal/keys convention' );
	is_deeply(
		$provider->{set_path_calls}[0]{data},
		{ key1 => 'FAKE-UNSEAL-KEY-1', key2 => 'FAKE-UNSEAL-KEY-2', key3 => 'FAKE-UNSEAL-KEY-3' },
		'writes all seal keys, numbered from 1'
	);
};

# --- skips the redundant/circular write --------------------------------------

subtest 'skips backup when deploying provider is the target itself' => sub {
	my $provider = MockVaultProvider->new( url => 'HTTPS://10.0.1.7:8200/' );
	my $self     = build_self( vault_provider => $provider );

	my $result = $self->_backup_seal_keys_to_provider( ['FAKE-UNSEAL-KEY-1'], 'https://10.0.1.7:8200' );

	is( $result, 0, 'reports no-op' );
	is( scalar @{ $provider->{set_path_calls} }, 0, 'never writes' );
};

# --- best-effort: never dies, never blocks init ------------------------------

subtest 'is best-effort when no deploying vault is configured' => sub {
	my $self = build_self( vault_error => 'no deploying vault is configured for this environment' );

	my $result = eval { $self->_backup_seal_keys_to_provider( ['FAKE-UNSEAL-KEY-1'], 'https://10.0.1.7:8200' ) };

	is( $@, '', 'does not propagate a die' );
	is( $result, 0, 'reports failure to the caller' );
};

subtest 'is best-effort when the deploying vault write fails' => sub {
	my $provider = MockVaultProvider->new( url => 'https://10.0.0.5:8200', set_path_error => 'connection refused' );
	my $self     = build_self( vault_provider => $provider );

	my $result = eval { $self->_backup_seal_keys_to_provider( ['FAKE-UNSEAL-KEY-1'], 'https://10.0.1.7:8200' ) };

	is( $@, '', 'does not propagate a die' );
	is( $result, 0, 'reports failure to the caller' );
};

subtest 'no-ops on an empty seal key list' => sub {
	my $provider = MockVaultProvider->new( url => 'https://10.0.0.5:8200' );
	my $self     = build_self( vault_provider => $provider );

	is( $self->_backup_seal_keys_to_provider( [], 'https://10.0.1.7:8200' ), 0, 'reports no-op for an empty list' );
	is( $self->_backup_seal_keys_to_provider( undef, 'https://10.0.1.7:8200' ), 0, 'reports no-op for undef' );
	is( scalar @{ $provider->{set_path_calls} }, 0, 'never writes' );
};

# --- wiring: _store_seal_keys must call the backup on success ---------------

subtest '_store_seal_keys calls _backup_seal_keys_to_provider after a successful store' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';

	my @run_calls;
	local *Genesis::Hook::Addon::Openbao::Init::run = sub {
		shift if ref( $_[0] ) eq 'HASH';
		my $cmd = join( ' ', @_ );
		push @run_calls, $cmd;
		return ( 'sealed: false', 0 ) if $cmd =~ /\bstatus\b/;
		return ( '', 0 )              if $cmd =~ /auth token/;
		return ( 'wrote', 0 )         if $cmd =~ /\bset\b.*seal\/keys:key/;
		return ( 'key1: xxx', 0 )     if $cmd =~ /\bget\b.*seal\/keys/;
		return ( '', 0 );
	};

	my @backup_calls;
	local *Genesis::Hook::Addon::Openbao::Init::_backup_seal_keys_to_provider = sub {
		my ( $self, $seal_keys, $target_url ) = @_;
		push @backup_calls, { seal_keys => $seal_keys, target_url => $target_url };
		return 1;
	};

	my $self = build_self();

	# Format must satisfy _store_seal_keys' key validation (base64/hex-like,
	# no punctuation), so use obviously-fake alphanumeric placeholders here
	# rather than the FAKE-UNSEAL-KEY-N style used elsewhere in this file.
	my $init_output = join( "\n",
		'Unseal Key 1: FAKEUNSEALKEY1',
		'Unseal Key 2: FAKEUNSEALKEY2',
		'Unseal Key 3: FAKEUNSEALKEY3',
		'Initial Root Token: FAKEROOTTOKEN',
	);

	my $result = $self->_store_seal_keys( $init_output, 'lab-openbao', 'https://10.0.1.7:8200' );

	is( $result, 1, '_store_seal_keys reports success' );
	is( scalar @backup_calls, 1, '_backup_seal_keys_to_provider was called exactly once' );
	is_deeply(
		$backup_calls[0]{seal_keys},
		[ 'FAKEUNSEALKEY1', 'FAKEUNSEALKEY2', 'FAKEUNSEALKEY3' ],
		'called with the parsed seal keys'
	);
	is( $backup_calls[0]{target_url}, 'https://10.0.1.7:8200', 'called with the target OpenBAO URL' );
};

# --- wiring: the auto-store branch in perform() must also back up ------------
#
# When `safe init` already writes the unseal keys itself, perform() takes the
# $safe_stored_keys branch and never calls _store_seal_keys - so today the
# backup call above never runs on that path. This drives perform() itself,
# mocking BOSH VM discovery and every `safe`/`curl` call via `run`, to prove
# the auto-store branch also reaches _backup_seal_keys_to_provider.

subtest 'perform backs up seal keys when safe init auto-stored them' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';

	my $init_output = join( "\n",
		'Unseal Key 1: FAKEUNSEALKEY1',
		'Unseal Key 2: FAKEUNSEALKEY2',
		'Unseal Key 3: FAKEUNSEALKEY3',
		'Initial Root Token: FAKEROOTTOKEN',
		'safe has written the unseal keys at secret/ocfp/lab/openbao/vault/seal/keys',
	);

	local *Genesis::Hook::Addon::Openbao::Init::read_json_from = sub {
		return ( { Tables => [ { Rows => [ { ips => '10.0.1.7' } ] } ] }, 0 );
	};

	local *Genesis::Hook::Addon::Openbao::Init::run = sub {
		shift if ref( $_[0] ) eq 'HASH';
		my $cmd = join( ' ', @_ );
		return ( '', 0 )         if $cmd =~ /^curl /;
		return ( '', 0 )         if $cmd =~ /\bsafe target\b/;
		return ( $init_output, 0 ) if $cmd =~ /\bsafe -T \S+ init\b/;
		return ( 'key1: xxx', 0 ) if $cmd =~ /\bsafe -T \S+ get\b/;
		return ( '', 0 );
	};

	my @backup_calls;
	local *Genesis::Hook::Addon::Openbao::Init::_backup_seal_keys_to_provider = sub {
		my ( $self, $seal_keys, $target_url ) = @_;
		push @backup_calls, { seal_keys => $seal_keys, target_url => $target_url };
		return 1;
	};

	my $env = MockEnv->new( secrets_base => 'secret/ocfp/lab/openbao/' );
	$env->{name} = 'lab-openbao';
	{
		no strict 'refs';
		*MockEnv::name = sub { $_[0]->{name} };
		*MockEnv::bosh = sub { $_[0] };
		*MockEnv::execute = sub { return '' };
	}

	my $self = bless { env_obj => $env }, 'Genesis::Hook::Addon::Openbao::Init';

	$self->perform;

	is( scalar @backup_calls, 1, '_backup_seal_keys_to_provider was called exactly once' );
	is_deeply(
		$backup_calls[0]{seal_keys},
		[ 'FAKEUNSEALKEY1', 'FAKEUNSEALKEY2', 'FAKEUNSEALKEY3' ],
		'called with the seal keys parsed from the auto-stored init output'
	);
	is( $backup_calls[0]{target_url}, 'https://10.0.1.7', 'called with the target OpenBAO URL' );
};

done_testing;
