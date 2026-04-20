package Genesis::Hook::CloudConfig::Openbao v1.0.0;

use v5.20;
use warnings; # Genesis min perl version is 5.20

# Only needed for development
BEGIN {push @INC, $ENV{GENESIS_LIB} ? $ENV{GENESIS_LIB} : $ENV{HOME}.'/.genesis/lib'}

use parent qw(Genesis::Hook::CloudConfig);

use Genesis::Hook::CloudConfig::Helpers qw/gigabytes megabytes/;

use Genesis qw//;
use JSON::PP;

sub init {
	my $class = shift;
	my $obj = $class->SUPER::init(@_);
	$obj->check_minimum_genesis_version('3.1.0');
	return $obj;
}

sub perform {
	my ($self) = @_;
	return 1 if $self->completed;

	my $config = $self->build_cloud_config({
		'networks' => [
			$self->network_definition('openbao', strategy => 'ocfp',
				dynamic_subnets => {
					allocation => {
						size => 0,
						statics => 0,
					},
					cloud_properties_for_iaas => {
						aws => {
							'subnet' => $self->subnet_reference('id'),
						},
						openstack => {
							'net_id' => $self->network_reference('id'),
							'security_groups' => ['default']
						},
						stackit => {
							'net_id' => $self->network_reference('id'),
							'security_groups' => $self->network_reference('sgs', 'get_sgs_by_names', 'ocfp', 'default'),
						},
					},
				}
			)
		],
		'vm_types' => [
			$self->vm_type_definition('openbao',
				cloud_properties_for_iaas => {
					aws => {
						'instance_type' => $self->for_scale({
							dev => 't3.medium',
							prod => 'm6i.large'
						}, 't3.medium'),
						'ephemeral_disk' => {
							'encrypted' => $self->TRUE,
							'size' => $self->for_scale({
								dev => 4096,
								prod => 16384
							}, 4096),
							'type' => 'gp3'
						},
						'metadata_options' => {
							'http_tokens' => 'required'
						},
					},
					openstack => {
						'instance_type' => $self->for_scale({
							dev => 'm1.2',
							prod => 'm1.3'
						}, 'm1.2'),
						'boot_from_volume' => $self->TRUE,
						'root_disk' => {
							'size' => 32
						},
					},
					stackit => {
						'instance_type' => $self->for_scale({
							dev => 'm1a.2d',
							prod => 'm1a.4d'
						}, 'm1a.2d'),
						'boot_from_volume' => $self->TRUE,
						'root_disk' => {
							'size' => 32
						},
					},
				},
			),
		],
		'disk_types' => [
			$self->disk_type_definition('openbao',
				common => {
					disk_size => $self->for_scale({
						dev => gigabytes(64),
						prod => gigabytes(128)
					}, gigabytes(96)),
				},
				cloud_properties_for_iaas => {
					aws => {
						'encrypted' => $self->TRUE,
						'type' => 'gp3',
					},
					openstack => {
						'type' => 'storage_premium_perf6',
					},
					stackit => {
						'type' => 'storage_premium_perf6',
					},
				},
			),
		],
		'vm_extensions' => [
			$self->vm_extension_definition('openbao-lb', {
					aws => {
						'lb_target_groups' => [$self->env->lookup(
							'cloud-config.openbao-lb-target-group',
							'ocfp-' . ( $ENV{GENESIS_ENVIRONMENT} || 'mgmt' ) . '-openbao-lb-tg'
						)]
					}
				}
			)
		],
	});

	$self->done($config);

	return 1;

}

sub get_sgs_by_names {
	my ($self, $subnet_data, $ref, @names) = @_;
	my @ids = map {$subnet_data->{$ref}{$_}{id}} @names;
	return \@ids
}
1;
# vim: set ts=2 sw=2 sts=2 noet fdm=marker foldlevel=1:
