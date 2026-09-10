package main;

use strictures 2;

use Carp       qw(croak);
use Cwd        qw(abs_path);
use English    qw(-no_match_vars);
use File::Path qw(make_path);
use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IPC::Open3 qw(open3);
use Symbol     qw(gensym);
use Test2::V0;

my $deploy_dir = abs_path(File::Spec->catdir($FindBin::Bin, File::Spec->updir, 'deploy', 'podman'));
my $installer  = File::Spec->catfile($deploy_dir, 'install.sh');

sub slurp {
  my ($path) = @_;
  open my $fh, '<', $path or croak "Can't read $path: $OS_ERROR";
  local $INPUT_RECORD_SEPARATOR = undef;
  return <$fh>;
}

sub write_file {
  my ($path, $text) = @_;
  open my $fh, '>', $path or croak "Can't write $path: $OS_ERROR";
  print {$fh} $text or croak "Can't write $path: $OS_ERROR";
  close $fh         or croak "Can't close $path: $OS_ERROR";
  return;
}

sub run_install {
  my (@args) = @_;
  my $stderr = gensym;
  my $pid    = open3(my $stdin, my $stdout, $stderr, 'bash', $installer, @args);
  close $stdin or croak "Can't close installer input: $OS_ERROR";
  local $INPUT_RECORD_SEPARATOR = undef;
  my $output = (<$stdout> // q{}) . (<$stderr> // q{});
  waitpid $pid, 0;
  return ($CHILD_ERROR >> 8, $output);
}

subtest 'packaged services agree on their authority and network' => sub {
  my $stack       = File::Spec->catdir($deploy_dir, 'stack');
  my $irc         = slurp(File::Spec->catfile($stack, 'overnet-irc.container'));
  my $relay       = slurp(File::Spec->catfile($stack, 'overnet-authority-relay.container'));
  my ($irc_url)   = $irc   =~ /--authority-relay-url\s+(\S+)/smx;
  my ($relay_url) = $relay =~ /--relay-url\s+(\S+)/smx;
  is $irc_url,   'ws://overnet-authority-relay:7448', 'IRC uses the container network endpoint';
  is $relay_url, $irc_url,                            'delegations use the same relay URL on both services';
  like $relay, qr{^ContainerName=overnet-authority-relay$}smx, 'endpoint matches the container DNS name';

  for my $unit ($irc, $relay) {
    like $unit, qr{^Network=overnet\.network$}smx, 'service joins the packaged network';
    while ($unit =~ /^(?:Network|Volume)=([^:\n]+)/gsmx) {
      ok -f File::Spec->catfile($stack, $1), "reference $1 is included in the package";
    }
  }
  like $irc,     qr{^After=overnet-authority-relay\.service$}smx, 'boot orders the relay before IRC';
  like $irc,     qr{--group-host\s+\S+}smx,                       'hosted channel handling is enabled';
  like $irc,     qr{^PublishPort=127\.0\.0\.1:6667:6667$}smx,     'IRC is private by default';
  unlike $relay, qr{^PublishPort=}smx,                            'relay needs no host port';
};

subtest 'installer executes the deployment without operator edits' => sub {
  if ($EFFECTIVE_USER_ID == 0) {
    plan skip_all => 'rootless installer requires a non-root user';
  }
  my $temp   = tempdir(CLEANUP => 1);
  my $bin    = File::Spec->catdir($temp,   'bin');
  my $config = File::Spec->catdir($temp,   'config with spaces');
  my $units  = File::Spec->catdir($config, 'containers', 'systemd');
  my $log    = File::Spec->catfile($temp, 'commands');
  make_path($bin);

  # These are the only service/container commands the installer may run.
  # Real copies and directory creation stay inside the temporary config tree.
  my $mock = <<'BASH';
#!/usr/bin/env bash
set -eu
call="${0##*/} $*"
printf '%s\n' "$call" >> "$OVERNET_TEST_LOG"
if [[ "${OVERNET_TEST_FAIL_COMMAND:-}" == "$call" ]]; then exit 1; fi
case "$call" in
  'systemctl --user show-environment' | 'systemctl --user daemon-reload' | \
  'systemctl --user restart overnet-authority-relay.service' | \
  'systemctl --user restart overnet-irc.service') exit 0 ;;
  *) echo "Unexpected command: $call" >&2; exit 2 ;;
esac
BASH
  for my $name (qw(podman systemctl)) {
    my $path = File::Spec->catfile($bin, $name);
    write_file($path, $mock);
    chmod 0755, $path or croak "Can't chmod $path: $OS_ERROR";
  }
  local $ENV{PATH}                      = "$bin:$ENV{PATH}";
  local $ENV{XDG_CONFIG_HOME}           = $config;
  local $ENV{OVERNET_TEST_LOG}          = $log;
  local $ENV{OVERNET_TEST_FAIL_COMMAND} = 'systemctl --user show-environment';

  my ($exit, $output) = run_install();
  isnt $exit, 0, 'missing user session fails';
  ok !-e $units, 'session failure leaves configuration untouched';

  local $ENV{OVERNET_TEST_FAIL_COMMAND} = q{};
  write_file($log, q{});
  ($exit, $output) = run_install();
  is $exit, 0, 'prepared deployment installs successfully';
  like $output, qr{Services\s+started}smx, 'reports service startup';
  my @names = qw(overnet.network overnet-irc.container overnet-irc.volume
    overnet-authority-relay.container overnet-authority-relay.volume);
  for my $name (@names) {
    is slurp(File::Spec->catfile($units, $name)),
      slurp(File::Spec->catfile($deploy_dir, 'stack', $name)),
      "installs $name directly from the package";
  }
  is [split /\n/smx, slurp($log)],
    [
    'systemctl --user show-environment',
    'systemctl --user daemon-reload',
    'systemctl --user restart overnet-authority-relay.service',
    'systemctl --user restart overnet-irc.service',
    ],
    'checks the user session, reloads, then starts relay before IRC';

  my $dropins = File::Spec->catdir($units, 'overnet-irc.container.d');
  make_path($dropins);
  my $custom = File::Spec->catfile($dropins, 'local.conf');
  write_file($custom, "[Service]\nRestartSec=5\n");
  ($exit, $output) = run_install();
  is $exit,          0,                           'installer can be rerun';
  is slurp($custom), "[Service]\nRestartSec=5\n", 'rerun preserves local drop-ins';

  local $ENV{OVERNET_TEST_FAIL_COMMAND} = 'systemctl --user restart overnet-authority-relay.service';
  write_file($log, q{});
  ($exit, $output) = run_install();
  isnt $exit, 0, 'relay startup failure propagates';
  unlike slurp($log), qr{restart\s+overnet-irc\.service}smx, 'does not start IRC after relay startup fails';
};

done_testing;

1;
