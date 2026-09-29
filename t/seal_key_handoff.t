#!/usr/bin/env perl
# Coverage for the seal-key handoff between hooks/pre-deploy.pm and
# hooks/post-deploy.pm.
#
# With standby reads forwarded to the active node, a lone unsealed node
# cannot answer any read until a second node is unsealed and a leader is
# elected. Post-deploy therefore hands the keys pre-deploy saved straight to
# the unseal addon, which submits them to every node's own sys/unseal,
# instead of unsealing the safe target and reading the stored keys back
# through it. Pre-deploy falls back to the init addon's backup copy in the
# deploying vault when the cluster itself cannot answer.
#
# Requires the real genesis Perl library on GENESIS_LIB or ~/.genesis/lib,
# same as the hooks themselves expect.

use v5.20;
use warnings;
use FindBin;
use File::Temp qw(tempdir);
use Test::More;

require "$FindBin::Bin/../hooks/post-deploy.pm";
require "$FindBin::Bin/../hooks/pre-deploy.pm";
require "$FindBin::Bin/../hooks/addon-unseal~u.pm";

my $tmp = tempdir( CLEANUP => 1 );

sub write_file {
	my ( $path, $content ) = @_;
	open( my $fh, '>', $path ) or die "cannot write $path: $!";
	print $fh $content;
	close($fh);
}

sub read_file {
	my ($path) = @_;
	open( my $fh, '<', $path ) or die "cannot read $path: $!";
	local $/;
	my $content = <$fh>;
	close($fh);
	return $content;
}

# --- post-deploy: _predeploy_seal_keys ------------------------------------------

subtest '_predeploy_seal_keys reads one well-formed key per line' => sub {
	my $file = "$tmp/predeploy-keys";
	write_file( $file, "KEYONE\n  KEYTWO  \n\nnot a key!\nKEYTHREE=" );
	local $ENV{GENESIS_PREDEPLOY_DATAFILE} = $file;

	my $self = bless {}, 'Genesis::Hook::PostDeploy::Openbao';
	is_deeply( $self->_predeploy_seal_keys, [ 'KEYONE', 'KEYTWO', 'KEYTHREE=' ], 'trims, and drops blank or malformed lines' );
};

subtest '_predeploy_seal_keys returns nothing without a datafile' => sub {
	local $ENV{GENESIS_PREDEPLOY_DATAFILE} = "$tmp/missing";
	my $self = bless {}, 'Genesis::Hook::PostDeploy::Openbao';
	is_deeply( $self->_predeploy_seal_keys, [], 'returns an empty list' );
};

# --- post-deploy: the sealed branch hands the keys to every node ------------------

subtest 'post-deploy hands the pre-deploy keys to the unseal addon when sealed' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';

	my $file = "$tmp/predeploy-sealed";
	write_file( $file, "KEYONE\nKEYTWO\nKEYTHREE" );
	local $ENV{GENESIS_PREDEPLOY_DATAFILE} = $file;
	local $ENV{GENESIS_DEPLOY_RC}          = 0;
	local $ENV{GENESIS_ENVIRONMENT}        = 'lab-openbao';

	my @safe_unseals;
	local *Genesis::Hook::PostDeploy::Openbao::run = sub {
		my $opts = ( ref( $_[0] ) eq 'HASH' ) ? shift : {};
		my $cmd  = join( ' ', @_ );
		push @safe_unseals, $cmd if $cmd =~ /safe .*unseal/;
		return ( '{"initialized": true, "sealed": true}', 2 ) if $cmd =~ /vault status -format=json/;
		return ( '', 1 );
	};
	local *Genesis::Hook::PostDeploy::Openbao::_ensure_target           = sub { };
	local *Genesis::Hook::PostDeploy::Openbao::_auto_init_if_needed     = sub { };
	local *Genesis::Hook::PostDeploy::Openbao::_setup_doomsday_approle  = sub { };
	my $instructions = 0;
	local *Genesis::Hook::PostDeploy::Openbao::_show_manual_instructions = sub { $instructions++ };

	my $handed;
	local *Genesis::Hook::PostDeploy::Openbao::_unseal_all_nodes = sub {
		my ( $self, $keys ) = @_;
		$handed = $keys;
		return 1;
	};

	my $self = bless {}, 'Genesis::Hook::PostDeploy::Openbao';
	$self->perform;

	is_deeply( $handed, [ 'KEYONE', 'KEYTWO', 'KEYTHREE' ], 'passes the pre-deploy keys to the per-node unseal' );
	is( scalar @safe_unseals, 0, 'no longer unseals only the safe target first' );
	is( $instructions, 0, 'shows no manual instructions once every node is unsealed' );
};

subtest '_unseal_all_nodes passes the keys into the addon' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';

	package MockKit { sub new { bless {}, shift } sub path { "$FindBin::Bin/../hooks/addon-unseal~u.pm" } }

	my %init_opts;
	local *Genesis::Hook::Addon::Openbao::Unseal::init = sub {
		my ( $class, %opts ) = @_;
		%init_opts = %opts;
		return bless {}, $class;
	};
	local *Genesis::Hook::Addon::Openbao::Unseal::perform = sub { return 1 };

	my $self = bless { kit => MockKit->new, env => 'env' }, 'Genesis::Hook::PostDeploy::Openbao';
	is( $self->_unseal_all_nodes( ['KEYONE'] ), 1, 'reports the addon result' );
	is_deeply( $init_opts{seal_keys}, ['KEYONE'], 'hands the keys to the addon' );
	is( $init_opts{allow_prompts}, 0, 'forbids prompts when the deploy is not interactive' );

	$self->{interactive} = 1;
	$self->_unseal_all_nodes();
	is_deeply( $init_opts{seal_keys}, [], 'hands an empty list when there are no keys' );
	is( $init_opts{allow_prompts}, 1, 'allows prompts when the deploy is interactive' );
};

subtest '_unseal_all_nodes reports failure when the addon dies or leaves nodes sealed' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';
	local *Genesis::Hook::Addon::Openbao::Unseal::init = sub { bless {}, $_[0] };

	my $self = bless { kit => MockKit->new, env => 'env' }, 'Genesis::Hook::PostDeploy::Openbao';
	{
		local *Genesis::Hook::Addon::Openbao::Unseal::perform = sub { return 0 };
		is( $self->_unseal_all_nodes( ['KEYONE'] ), 0, 'returns 0 when nodes stay sealed' );
	}
	{
		local *Genesis::Hook::Addon::Openbao::Unseal::perform = sub { die "boom\n" };
		is( $self->_unseal_all_nodes( ['KEYONE'] ), 0, 'returns 0 when the addon dies' );
	}
};

# --- pre-deploy: falls back to the deploying vault backup ---------------------------

package MockService {
	sub new { my ( $c, %a ) = @_; bless {%a}, $c }
	sub get { my ( $self, $path ) = @_; push @{ $self->{reads} }, $path; return $self->{data} }
}
package MockStore  { sub new { my ( $c, %a ) = @_; bless {%a}, $c } sub service { $_[0]->{service} } }
package MockPreEnv {
	sub new { my ( $c, %a ) = @_; bless {%a}, $c }
	sub name          { 'lab-openbao' }
	sub notify        { }
	sub secrets_base  { '/secret/lab/openbao/' }
	sub secrets_store { $_[0]->{store} }
}

package main;

subtest 'pre-deploy uses the deploying vault backup when the cluster has no target' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';

	my $file = "$tmp/predeploy-out";
	local $ENV{GENESIS_PREDEPLOY_DATAFILE} = $file;
	local *Service::Vault::find_by_target = sub { return () };

	my $service = MockService->new( data => { key2 => 'BACKUPTWO', key1 => 'BACKUPONE', root_token => 'NOTAKEY' } );
	my $env     = MockPreEnv->new( store => MockStore->new( service => $service ) );
	my $self    = bless { env => $env }, 'Genesis::Hook::PreDeploy::Openbao';

	$self->perform;

	is( read_file($file), "BACKUPONE\nBACKUPTWO", 'writes the backup keys in key-number order' );
	is_deeply( $service->{reads}, ['/secret/lab/openbao/vault/seal/keys'], 'reads the backup under secrets_base' );
};

subtest 'pre-deploy prefers the cluster copy when it answers' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';

	package MockCluster {
		sub new { bless {}, shift }
		sub has { $_[1] eq 'secret/vault/seal/keys' }
		sub get {
			my ( $self, $path ) = @_;
			die "wrong path $path\n" unless $path eq 'secret/vault/seal/keys';
			return { key1 => 'CLUSTERONE', key2 => 'CLUSTERTWO' };
		}
	}

	my $file = "$tmp/predeploy-cluster";
	local $ENV{GENESIS_PREDEPLOY_DATAFILE} = $file;
	local *Service::Vault::find_by_target = sub { return ( MockCluster->new ) };

	my $service = MockService->new( data => { key1 => 'BACKUPONE' } );
	my $env     = MockPreEnv->new( store => MockStore->new( service => $service ) );
	my $self    = bless { env => $env }, 'Genesis::Hook::PreDeploy::Openbao';

	$self->perform;

	is( read_file($file), "CLUSTERONE\nCLUSTERTWO", 'writes the cluster keys from the exact primary path' );
	ok( !$service->{reads}, 'never reads the backup copy' );
};

subtest 'pre-deploy falls back when the cluster target exists but cannot answer' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';

	package SealedCluster {
		sub new { bless {}, shift }
		sub has { die "sealed\n" }
		sub get { die "sealed\n" }
	}

	my $file = "$tmp/predeploy-sealed-cluster";
	local $ENV{GENESIS_PREDEPLOY_DATAFILE} = $file;
	local *Service::Vault::find_by_target = sub { return ( SealedCluster->new ) };

	my $service = MockService->new( data => { key1 => 'BACKUPONE', key2 => 'BACKUPTWO' } );
	my $env     = MockPreEnv->new( store => MockStore->new( service => $service ) );
	my $self    = bless { env => $env }, 'Genesis::Hook::PreDeploy::Openbao';

	$self->perform;

	is( read_file($file), "BACKUPONE\nBACKUPTWO", 'writes the backup keys' );
};

subtest 'pre-deploy writes nothing and still succeeds when no source has keys' => sub {
	no strict 'refs';
	no warnings 'redefine', 'once';

	package EmptyCluster {
		sub new { bless {}, shift }
		sub has { 1 }
		sub get { {} }
	}

	my $file = "$tmp/predeploy-empty";
	local $ENV{GENESIS_PREDEPLOY_DATAFILE} = $file;
	local *Service::Vault::find_by_target = sub { return ( EmptyCluster->new ) };

	my $env  = MockPreEnv->new( store => MockStore->new( service => MockService->new( data => {} ) ) );
	my $self = bless { env => $env }, 'Genesis::Hook::PreDeploy::Openbao';

	is( $self->perform, 1, 'returns success so the deploy goes ahead' );
	ok( !-e $file, 'writes no key file' );
};

done_testing;
