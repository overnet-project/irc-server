use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "Can't open $path: $!";
  local $/ = undef;
  return <$fh>;
}

my $code_root  = File::Spec->catdir($FindBin::Bin, '..');
my $podman_dir = File::Spec->catdir($code_root, 'deploy', 'podman');
my $containerfile  = File::Spec->catfile($podman_dir, 'Containerfile');
my $container_unit = File::Spec->catfile($podman_dir, 'overnet-irc.container');
my $volume_unit    = File::Spec->catfile($podman_dir, 'overnet-irc.volume');
my $readme         = File::Spec->catfile($podman_dir, 'README.md');
my $smoke_test     = File::Spec->catfile($podman_dir, 'smoke-test.sh');
my $quadlet_check  = File::Spec->catfile($podman_dir, 'quadlet-check.sh');
my $workflow = File::Spec->catfile($code_root, '.github', 'workflows', 'container.yml');

ok -f $containerfile,  'Containerfile exists';
ok -f $container_unit, 'Quadlet .container unit exists';
ok -f $volume_unit,    'Quadlet .volume unit exists';
ok -f $readme,         'podman deploy README exists';
ok -f $smoke_test && -s $smoke_test,       'smoke-test script exists and is non-empty';
ok -x $smoke_test,                         'smoke-test script is executable';
ok -f $quadlet_check && -s $quadlet_check, 'quadlet-check script exists and is non-empty';
ok -x $quadlet_check,                      'quadlet-check script is executable';
ok -f $workflow,                           'container-build workflow exists';

my $containerfile_text = _slurp($containerfile);
like $containerfile_text, qr{^FROM\s+\S*perl:}mx,
  'Containerfile builds on a perl base image';
for my $sibling (qw(core-perl relay-perl adapter-irc-perl irc-server)) {
  like $containerfile_text, qr{COPY\s+\Q$sibling\E\b}mx,
    "Containerfile copies the $sibling checkout";
}
like $containerfile_text, qr{PERL5LIB=\S*core-perl/lib\S*relay-perl/lib}mx,
  'Containerfile exposes core-perl and relay-perl on PERL5LIB';
like $containerfile_text, qr{Crypt-PK-ECC-Schnorr}mx,
  'Containerfile pre-installs the unindexed Schnorr dist Net::Nostr::Core needs';
like $containerfile_text, qr{\blibgmp-dev\b}mx,
  'Containerfile installs libgmp-dev for Math::GMPz (a Schnorr dependency)';
like $containerfile_text, qr{--installdeps\b}mx,
  'Containerfile installs CPAN prerequisites';
like $containerfile_text, qr{overnet-irc-server["\s,\]]+service}mx,
  'Containerfile entrypoint runs the IRC service command';
like $containerfile_text, qr{^USER\s+overnet}mx,
  'Containerfile drops to an unprivileged user';
like $containerfile_text, qr{^EXPOSE\s+6667}mx,
  'Containerfile exposes the IRC listener port';

my $container_unit_text = _slurp($container_unit);
like $container_unit_text, qr{^\[Container\]}mx,
  'Quadlet unit declares a [Container] section';
like $container_unit_text, qr{^Image=}mx,
  'Quadlet unit sets an image';
like $container_unit_text, qr{^Volume=overnet-irc\.volume:}mx,
  'Quadlet unit mounts the state volume by the .volume unit file name';
like $container_unit_text, qr{^PublishPort=127\.0\.0\.1:6667:6667}mx,
  'Quadlet unit publishes the listener on loopback by default';
like $container_unit_text, qr{--signing-key-file\s+/var/lib/overnet/irc/}mx,
  'Quadlet unit keeps the signing key on the mounted volume';
like $container_unit_text, qr{--health-file\s+/var/lib/overnet/irc/}mx,
  'Quadlet unit keeps the health file on the mounted volume';
like $container_unit_text, qr{^HealthCmd=}mx,
  'Quadlet unit defines a health check';

my $volume_unit_text = _slurp($volume_unit);
like $volume_unit_text, qr{^\[Volume\]}mx,
  'Quadlet volume unit declares a [Volume] section';
like $volume_unit_text, qr{^VolumeName=overnet-irc-state}mx,
  'Quadlet volume unit names the state volume';

# The state path baked into the Containerfile, the Quadlet Exec= line, and the
# volume mount must agree, or the signing key would not persist.
like $containerfile_text, qr{/var/lib/overnet/irc}mx,
  'Containerfile state path matches the mounted volume path';
like $container_unit_text, qr{Volume=overnet-irc\.volume:/var/lib/overnet/irc:}mx,
  'Quadlet mount path matches the configured state path';

# Setting VolumeName= makes podman use that name verbatim (no systemd- prefix),
# so the README must inspect the volume by exactly that name.
my ($volume_name) = $volume_unit_text =~ /^VolumeName=(\S+)/mx;
ok $volume_name, 'volume unit sets an explicit VolumeName';
my $readme_text = _slurp($readme);
like $readme_text, qr{podman\s+volume\s+inspect\s+\Q$volume_name\E\b}mx,
  'README inspects the volume by its actual (unprefixed) name';
unlike $readme_text, qr{systemd-\Q$volume_name\E}mx,
  'README does not reference the systemd- prefixed name VolumeName suppresses';

like $readme_text, qr{podman\s+build}mx,
  'README documents building the image';
like $readme_text, qr{\.config/containers/systemd}mx,
  'README documents the rootless Quadlet install path';

my $workflow_text = _slurp($workflow);
like $workflow_text, qr{podman\s+build}mx, 'workflow builds the image';
like $workflow_text, qr{\bContainerfile\b}mx, 'workflow builds from the Containerfile';
like $workflow_text, qr{smoke-test\.sh}mx, 'workflow runs the smoke test';
like $workflow_text, qr{quadlet-check\.sh}mx, 'workflow runs the Quadlet check';
for my $sibling (qw(core-perl relay-perl adapter-irc-perl)) {
  like $workflow_text, qr{overnet-project/\Q$sibling\E}mx,
    "workflow checks out the $sibling sibling";
}

done_testing;
