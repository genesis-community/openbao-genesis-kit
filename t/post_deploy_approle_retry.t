#!/usr/bin/env perl
# Unit-level coverage for hooks/post-deploy.pm's
# _enable_approle_with_retry / _setup_doomsday_approle.
#
# `safe ... vault auth enable approle` can run before the bloc-vault is
# reliably ready (e.g. Raft leader election still settling right after a
# fresh deploy), even though `auth status` already succeeded moments
# earlier - producing a non-fatal "Could not enable approle auth" warning
# that a moment's retry would have avoided (seen on drgao).
# _enable_approle_with_retry adds a bounded backoff around the enable call;
# this drives it directly against a minimal mock $self, mirroring the other
# t/*.t files in this kit.
#
# Requires the real genesis Perl library on GENESIS_LIB or ~/.genesis/lib,
# same as the hook itself expects.

use v5.20;
use warnings;
use FindBin;
use Test::More;

require "$FindBin::Bin/../hooks/post-deploy.pm";

local $ENV{GENESIS_ENVIRONMENT} = 'lab-openbao';

sub build_self {
	return bless {}, 'Genesis::Hook::PostDeploy::Openbao';
}

# Installs a `run()` stub driven by a list of canned (out, rc) responses,
# one per call, so tests can assert exactly how many attempts were made.
sub install_run_sequence {
	my (@responses) = @_;
	my @calls;
	no strict 'refs';
	no warnings 'redefine', 'once';
	*Genesis::Hook::PostDeploy::Openbao::run = sub {
		my $opts = ( ref( $_[0] ) eq 'HASH' ) ? shift : {};
		push @calls, { opts => $opts, args => [@_] };
		my $resp = @responses > 1 ? shift(@responses) : $responses[0];
		return @$resp;
	};
	return \@calls;
}

# Installs a `_backoff_sleep` stub that records the requested duration
# instead of actually sleeping, so this suite runs in well under a second.
sub install_sleep_stub {
	my @sleeps;
	no strict 'refs';
	no warnings 'redefine', 'once';
	*Genesis::Hook::PostDeploy::Openbao::_backoff_sleep = sub {
		my ( $self, $seconds ) = @_;
		push @sleeps, $seconds;
		return;
	};
	return \@sleeps;
}

# --- succeeds immediately -----------------------------------------------------

subtest 'succeeds on the first attempt without retrying' => sub {
	my $self   = build_self();
	my $calls  = install_run_sequence( [ 'Success! Enabled approle auth method', 0 ] );
	my $sleeps = install_sleep_stub();

	my ( $out, $ok ) = $self->_enable_approle_with_retry;

	is( $ok, 1, 'reports success' );
	is( scalar @$calls, 1, 'made exactly one attempt' );
	is( scalar @$sleeps, 0, 'never backs off when the first attempt succeeds' );
};

# --- preserves the "already enabled" success handling --------------------------

subtest 'treats "path is already in use" as success, unchanged' => sub {
	my $self   = build_self();
	my $calls  = install_run_sequence( [ "path is already in use at approle/\n", 0 ] );
	my $sleeps = install_sleep_stub();

	my ( $out, $ok ) = $self->_enable_approle_with_retry;

	is( $ok, 1, 'reports success' );
	is( scalar @$calls, 1, 'made exactly one attempt' );
	is( scalar @$sleeps, 0, 'does not retry an already-enabled auth method' );
};

# --- succeeds after a transient failure, without exhausting the budget --------

subtest 'stops retrying as soon as a later attempt succeeds' => sub {
	my $self  = build_self();
	my $calls = install_run_sequence(
		[ 'connection refused',                  0 ],
		[ 'connection refused',                  0 ],
		[ 'Success! Enabled approle auth method', 0 ],
	);
	my $sleeps = install_sleep_stub();

	my ( $out, $ok ) = $self->_enable_approle_with_retry;

	is( $ok, 1, 'eventually reports success' );
	is( scalar @$calls, 3, 'made exactly three attempts' );
	is( scalar @$sleeps, 2, 'backed off between attempts, but stopped once unseal succeeded' );
};

# --- bounded: gives up (non-fatally) after the retry budget is exhausted ------

subtest 'gives up after a bounded number of attempts, capped near 30s' => sub {
	my $self   = build_self();
	my $calls  = install_run_sequence( [ 'connection refused', 0 ] );    # never succeeds
	my $sleeps = install_sleep_stub();

	my ( $out, $ok ) = $self->_enable_approle_with_retry;

	is( $ok, 0, 'reports failure rather than looping forever' );
	is( $out, 'connection refused', 'returns the last failure output for the warning message' );

	my $total_wait = 0;
	$total_wait += $_ for @$sleeps;

	ok( $total_wait > 0,  'backed off at least once' );
	ok( $total_wait <= 30, "total backoff stays within the ~30s cap (was ${total_wait}s)" );
	is( scalar @$calls, scalar(@$sleeps) + 1, 'makes one more attempt than it backs off' );
};

# --- _setup_doomsday_approle wiring: non-fatal warning on exhaustion ----------

subtest '_setup_doomsday_approle warns non-fatally when the retry budget is exhausted' => sub {
	my $self = build_self();

	no strict 'refs';
	no warnings 'redefine', 'once';

	local *Genesis::Hook::PostDeploy::Openbao::run = sub {
		my $opts = ( ref( $_[0] ) eq 'HASH' ) ? shift : {};
		my $cmd  = join( ' ', @_ );
		return ( "Initialized true\nSealed false\n", 0 ) if $cmd =~ /vault status/;
		return ( '', 0 )                               if $cmd =~ /auth status/;
		return ( '', 0 );
	};

	my $retry_calls = 0;
	local *Genesis::Hook::PostDeploy::Openbao::_enable_approle_with_retry = sub {
		$retry_calls++;
		return ( 'still not ready', 0 );
	};

	my $died = eval { $self->_setup_doomsday_approle; 1 };

	ok( $died, 'does not die - stays non-fatal' );
	is( $retry_calls, 1, 'delegates enabling to the bounded retry helper' );
};

done_testing;
