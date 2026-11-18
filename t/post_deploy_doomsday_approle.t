#!/usr/bin/env perl
# Unit-level coverage for hooks/post-deploy.pm's _setup_doomsday_approle.
#
# The doomsday kit reads this deployment's doomsday AppRole from the
# deployment's exodus data in the deploying vault, the same place the vault
# kit stores it.  These tests drive the sub against a stubbed `run()` for the
# deployed OpenBAO and a mock deploying-vault provider, and check that:
#
#   - the role ID, secret ID, and secret ID accessor land at the exodus base
#     in the deploying vault, and nothing is written to the deployed OpenBAO's
#     own exodus mount;
#   - no secret value ever appears in argv, only on stdin;
#   - the role is created with `vault write`, not `safe set`;
#   - earlier secret IDs are destroyed before a new one is minted, and a
#     minted secret ID that can't be stored is destroyed again.
#
# Requires the real genesis Perl library on GENESIS_LIB or ~/.genesis/lib,
# same as the hook itself expects.

use v5.20;
use warnings;
use FindBin;
use Test::More;
use JSON::PP;

require "$FindBin::Bin/../hooks/post-deploy.pm";

local $ENV{GENESIS_ENVIRONMENT} = 'lab-mgmt';
local $ENV{GENESIS_EXODUS_MOUNT} = '/secret/exodus/';
delete local $ENV{GENESIS_EXODUS_BASE};

use constant ROLE_ID   => 'FAKE-ROLE-ID-0000';
use constant SECRET_ID => 'FAKE-SECRET-ID-1111';
use constant ACCESSOR  => 'fake-accessor-2222';
use constant EXODUS    => '/secret/exodus/lab-mgmt/openbao';

# --- minimal mocks -----------------------------------------------------------

package MockProvider;
sub new { my ($c, %a) = @_; bless {queries => [], has => {}, %a}, $c }
sub url { 'https://10.0.0.5' }
sub has {
	my ($s, $path, $key) = @_;
	return $s->{has}{"$path:$key"} ? 1 : 0;
}
sub query {
	my $s    = shift;
	my $opts = ref($_[0]) eq 'HASH' ? shift : {};
	push @{$s->{queries}}, {opts => $opts, args => [@_]};
	return $s->{fail_set} ? ('', 1, 'permission denied') : ('', 0, '');
}

package MockEnv;
sub new { my ($c, %a) = @_; bless {%a}, $c }
sub vault { die "no deploying vault\n" unless $_[0]->{vault}; $_[0]->{vault} }
sub exodus_base { main::EXODUS() }

package main;

sub build_self {
	my (%opts) = @_;
	my $self = bless {}, 'Genesis::Hook::PostDeploy::Openbao';
	$self->{mock_env} = MockEnv->new(vault => $opts{provider});
	return $self;
}

{
	no strict 'refs';
	no warnings 'redefine', 'once';
	*Genesis::Hook::PostDeploy::Openbao::env = sub { $_[0]->{mock_env} };
	*Genesis::Hook::PostDeploy::Openbao::_backoff_sleep = sub { return };
}

# Installs a `run()` stub that answers the deployed OpenBAO's commands.
sub install_run {
	my (%opts) = @_;
	my @calls;
	no strict 'refs';
	no warnings 'redefine', 'once';
	*Genesis::Hook::PostDeploy::Openbao::run = sub {
		my $o = ref($_[0]) eq 'HASH' ? shift : {};
		my @args = @_;
		push @calls, {opts => $o, args => [@args]};
		my $cmd = join(' ', @args);
		return ("Initialized true\nSealed false\n", 0) if $cmd =~ /vault status$/;
		return ('', 0)                                 if $cmd =~ / auth status$/;
		return ("path is already in use at approle/\n", 2) if $cmd =~ /auth enable approle/;
		if ($cmd =~ /vault list -format=json auth\/approle\/role$/) {
			return (encode_json($opts{roles} // []), 0);
		}
		if ($cmd =~ /vault list -format=json auth\/approle\/role\/doomsday\/secret-id$/) {
			return ('', 2, 'No value found at auth/approle/role/doomsday/secret-id') unless @{$opts{accessors} // []};
			return (encode_json($opts{accessors}), 0);
		}
		return ('Success! Uploaded policy: doomsday', 0) if $cmd =~ /vault policy write doomsday -$/;
		return ('Success! Data written to: auth/approle/role/doomsday', 0)
			if $cmd =~ /vault write auth\/approle\/role\/doomsday /;
		return (ROLE_ID . "\n", 0) if $cmd =~ /get auth\/approle\/role\/doomsday\/role-id:role_id$/;
		return ('', 0) if $cmd =~ /secret-id-accessor\/destroy/;
		if ($cmd =~ /vault write -format=json -f auth\/approle\/role\/doomsday\/secret-id$/) {
			return (encode_json({data => {secret_id => SECRET_ID, secret_id_accessor => ACCESSOR}}), 0);
		}
		return ('unexpected command', 1);
	};
	return \@calls;
}

sub argv_strings {
	my (@lists) = @_;
	return map {@{$_->{args}}} @lists;
}

# --- writes the credentials to the exodus base in the deploying vault --------

subtest 'stores the approle in the deploying vault exodus, through stdin' => sub {
	my $provider = MockProvider->new;
	my $self     = build_self(provider => $provider);
	my $calls    = install_run(roles => []);

	$self->_setup_doomsday_approle;

	my @sets = grep {$_->{args}[0] eq 'set'} @{$provider->{queries}};
	is(scalar(@sets), 2, 'writes the role ID and the secret ID in two writes');
	is($sets[0]{args}[1], EXODUS, 'writes the role ID at the exodus base');
	is($sets[0]{args}[2], 'doomsday_approle_id@-', 'reads the role ID from stdin');
	is($sets[0]{opts}{stdin}, ROLE_ID, 'hands the role ID on stdin');
	is($sets[1]{args}[1], EXODUS, 'writes the secret ID at the exodus base');
	is($sets[1]{args}[2], 'doomsday_approle_secret@-', 'reads the secret ID from stdin');
	is($sets[1]{opts}{stdin}, SECRET_ID, 'hands the secret ID on stdin');
	is($sets[1]{args}[3], 'doomsday_approle_secret_accessor=' . ACCESSOR, 'records the accessor beside it');

	my @argv = (argv_strings(@$calls), argv_strings(@{$provider->{queries}}));
	ok(!(grep {/\Q${\ROLE_ID}\E|\Q${\SECRET_ID}\E/} @argv), 'no secret value appears in any argv');

	ok(!(grep {($_->{args}[3] // "") eq "set"} @$calls), 'never runs safe set against the deployed OpenBAO');
	ok(!(grep {grep {$_ eq $ENV{GENESIS_EXODUS_MOUNT}} @{$_->{args}}} @$calls),
		'never writes to the exodus mount on the deployed OpenBAO');
	ok((grep {join(" ", @{$_->{args}}) =~ /vault write auth\/approle\/role\/doomsday .*policies=doomsday/} @$calls),
		'creates the role with vault write');

	my ($policy) = grep {join(' ', @{$_->{args}}) =~ /vault policy write doomsday -$/} @$calls;
	like($policy->{opts}{stdin} // '', qr/path "secret\/\*"/, 'hands the policy on stdin');

	my ($mint) = grep {join(' ', @{$_->{args}}) =~ /secret-id$/ && join(' ', @{$_->{args}}) =~ /vault write/} @$calls;
	ok($mint->{opts}{redact_output}, 'keeps the minted secret ID out of the trace');
};

# --- skips when the role and its exodus copy are already there ---------------

subtest 'leaves an existing role alone when exodus already holds it' => sub {
	my $provider = MockProvider->new(has => {
		EXODUS . ':doomsday_approle_id'     => 1,
		EXODUS . ':doomsday_approle_secret' => 1,
	});
	my $self  = build_self(provider => $provider);
	my $calls = install_run(roles => ['doomsday']);

	$self->_setup_doomsday_approle;

	ok(!(grep {$_->{args}[0] eq 'set'} @{$provider->{queries}}), 'writes nothing to exodus');
	ok(!(grep {join(' ', @{$_->{args}}) =~ /secret-id$/ && join(' ', @{$_->{args}}) =~ /vault write/} @$calls),
		'mints no secret ID');
};

# --- destroys earlier secret IDs before minting -------------------------------

subtest 'destroys every earlier secret ID before minting a new one' => sub {
	my $provider = MockProvider->new;
	my $self     = build_self(provider => $provider);
	my $calls    = install_run(roles => ['doomsday'], accessors => ['old-accessor-1', 'old-accessor-2']);

	$self->_setup_doomsday_approle;

	my @cmds = map {join(' ', @{$_->{args}})} @$calls;
	my @destroyed = map {/secret_id_accessor=(\S+)/ ? $1 : ()} grep {/secret-id-accessor\/destroy/} @cmds;
	is_deeply(\@destroyed, ['old-accessor-1', 'old-accessor-2'], 'destroys both earlier secret IDs');

	my ($mint_at) = grep {$cmds[$_] =~ /vault write -format=json -f .*secret-id$/} 0..$#cmds;
	my ($last_destroy) = reverse grep {$cmds[$_] =~ /secret-id-accessor\/destroy/} 0..$#cmds;
	ok(defined($mint_at) && $last_destroy < $mint_at, 'destroys them before minting');
};

# --- destroys a minted secret ID it could not store ----------------------------

subtest 'destroys the minted secret ID when exodus cannot be written' => sub {
	my $provider = MockProvider->new(fail_set => 1);
	my $self     = build_self(provider => $provider);
	my $calls    = install_run(roles => []);

	$self->_setup_doomsday_approle;

	my @destroyed = map {/secret_id_accessor=(\S+)/ ? $1 : ()}
		grep {/secret-id-accessor\/destroy/} map {join(' ', @{$_->{args}})} @$calls;
	is_deeply(\@destroyed, [ACCESSOR], 'destroys the secret ID nobody holds');
};

# --- skips cleanly without a deploying vault ----------------------------------

subtest 'skips without touching OpenBAO when no deploying vault resolves' => sub {
	my $self  = build_self(provider => undef);
	my $calls = install_run(roles => []);

	my $ok = eval {$self->_setup_doomsday_approle; 1};
	ok($ok, 'does not die');
	ok(!(grep {join(' ', @{$_->{args}}) =~ /auth enable|policy write|vault write/} @$calls),
		'changes nothing on the deployed OpenBAO');
};

done_testing;
