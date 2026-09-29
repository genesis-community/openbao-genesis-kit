package Genesis::Hook::PreDeploy::Openbao v1.0.0;

use v5.20;
use warnings;

# Only needed for development
BEGIN {push @INC, $ENV{GENESIS_LIB} ? $ENV{GENESIS_LIB} : $ENV{HOME}.'/.genesis/lib'}

use parent qw(Genesis::Hook);

use Genesis qw/info run mkfile_or_fail/;
# Note: Service::Vault is a Genesis framework module for safe CLI interactions.
# It works with OpenBAO unchanged since the APIs are compatible.
use Service::Vault;

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

	# We're just grabbing the vault unseal keys for post-deploy unsealing.
	# The cluster's own copy comes first; when the cluster cannot answer (for
	# example because every node is sealed), the backup copy the init addon
	# wrote to the deploying vault is the fallback.
	$self->env->notify(" #iu{pre-deploy}: Retrieving unseal keys for post-deploy unsealing");
	my ($keys, $source) = $self->_keys_from_cluster;
	($keys, $source) = $self->_keys_from_deploying_vault unless $keys && @$keys;

	unless ($keys && @$keys) {
		info(
			'[[  - #Yr{#@{!} warning} >>no unseal keys found in the cluster or '.
			'in the deploying vault - automatic unseal will not be available'
		);
		return $self->done(1);
	}

	info(
		'[[  - >>found %d unseal keys at '.
		'[#C{%s}:key[1-N]] - '.
		'automatic unseal will be available after deployment',
		scalar(@$keys), $source
	);
	mkfile_or_fail($ENV{GENESIS_PREDEPLOY_DATAFILE}, join("\n", @$keys));

	return $self->done(1);
}
# }}}

# _keys_from_cluster - read the seal keys stored in the target cluster {{{
# Returns (\@keys, $path), or an empty list when the cluster has no target,
# no seal path, or cannot answer.
sub _keys_from_cluster {
	my ($self) = @_;

	my @matching_vaults = Service::Vault->find_by_target($self->env->name);
	return () unless @matching_vaults;
	my $vault = $matching_vaults[0];

	# The init addon stores the primary copy at exactly this path. Matching
	# any */vault/seal/keys path would also match other environments' backup
	# copies once this cluster holds their secrets, and hand over wrong keys.
	my $vault_seal_path = 'secret/vault/seal/keys';
	unless (eval { $vault->has($vault_seal_path) }) {
		info(
			'[[  - #Yr{#@{!} warning} >>Seal keys path not found in the cluster - '.
			'checking the deploying vault for a backup copy'
		);
		return ();
	}

	my $data = eval { $vault->get($vault_seal_path) };
	return (_seal_key_values($data), $vault_seal_path);
}
# }}}

# _keys_from_deploying_vault - read the init addon's backup copy {{{
# The init addon backs the keys up under this env's secrets_base in the
# deploying vault (see _backup_seal_keys_to_provider in addon-init~i.pm).
# Returns (\@keys, $path), or an empty list when there is no copy.
sub _keys_from_deploying_vault {
	my ($self) = @_;

	my $path = eval { $self->env->secrets_base() . 'vault/seal/keys' };
	return () unless $path;
	my $data = eval { $self->env->secrets_store->service->get($path) };
	my $keys = _seal_key_values($data);
	return () unless @$keys;
	return ($keys, $path);
}
# }}}

# _seal_key_values - the key1..keyN values of a seal keys secret, in order {{{
sub _seal_key_values {
	my ($data) = @_;
	return [] unless ref($data) eq 'HASH';
	my @names = sort { ($a =~ /(\d+)$/)[0] <=> ($b =~ /(\d+)$/)[0] }
		grep { /^key\d+$/ } keys %$data;
	return [ grep { defined($_) && $_ ne '' } map { $data->{$_} } @names ];
}
# }}}

1;
# vim: set ts=2 sw=2 sts=2 noet fdm=marker foldlevel=1:
