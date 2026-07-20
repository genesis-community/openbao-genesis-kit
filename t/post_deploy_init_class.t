#!/usr/bin/env perl
# Regression coverage for the post-deploy auto-init crash:
#   Can't locate object method "init" via package
#   "Genesis::Hook::Addon::OpenBao::Init"
#
# hooks/post-deploy.pm loads the init addon and calls ->init on a hard-coded
# package name. That name must match the package addon-init~i.pm actually
# declares, or auto-init dies at runtime after a successful deploy. This test
# extracts the class name post-deploy.pm invokes and proves it resolves to a
# package that can('init'), catching any case/spelling drift between the two
# files.
#
# Requires the real genesis Perl library on PERL5LIB (or ~/.genesis/lib),
# same as the hooks themselves expect.

use v5.20;
use warnings;
use FindBin;
use Test::More;

my $post_deploy = "$FindBin::Bin/../hooks/post-deploy.pm";
my $addon_init  = "$FindBin::Bin/../hooks/addon-init~i.pm";

# --- extract the init-addon class name post-deploy.pm invokes ---------------

open my $fh, '<', $post_deploy or die "cannot open $post_deploy: $!";
my $source = do { local $/; <$fh> };
close $fh;

my ($class) = $source =~ /(Genesis::Hook::Addon::\w+::Init)\s*->\s*init\b/;
ok($class, 'post-deploy.pm invokes an init-addon class via ->init')
	or BAIL_OUT('could not find the init-addon ->init call in post-deploy.pm');

# --- the class it names must exist and be able to ->init --------------------

require $addon_init;

ok($class->can('init'),
	"post-deploy.pm calls ->init on $class, which must be a loadable package that can('init')");

done_testing;
