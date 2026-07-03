use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-irc-server');

ok -f $script, 'IRC command exists'
  or bail_out('overnet-irc-server is required');

my $help = _run('--help');
is $help->{exit}, 0, 'top-level --help exits successfully';
like $help->{stdout}, qr/Usage:\s+overnet-irc-server\s+<command>\s+\[options\]/smx,
  'top-level usage names dispatcher';
like $help->{stdout}, qr/\bauth\b/mx,                    'top-level help lists auth';
like $help->{stdout}, qr/\bproxy\b/mx,                   'top-level help lists proxy';
like $help->{stdout}, qr/\bserver\b/mx,                  'top-level help lists server';
like $help->{stdout}, qr/\bauthority-relay-service\b/mx, 'top-level help lists authority relay service';

my $missing = _run();
is $missing->{exit}, 1, 'missing command exits unsuccessfully';
like $missing->{stderr}, qr/Usage:\s+overnet-irc-server\s+<command>\s+\[options\]/smx,
  'missing command prints top-level usage';

my $proxy_help = _run('help', 'proxy');
is $proxy_help->{exit}, 0, 'help proxy exits successfully';
like $proxy_help->{stdout}, qr/overnet-irc-server\s+proxy\s+\[options\]/mx, 'help proxy delegates to proxy usage';

my $service_help = _run('service', '--help');
is $service_help->{exit}, 0, 'service --help exits successfully';
like $service_help->{stdout}, qr/Usage:\s+overnet-irc-server\s+service\s+\[options\]/smx,
  'service help is command scoped';

my $unknown = _run('not-a-command');
is $unknown->{exit}, 1, 'unknown command exits unsuccessfully';
like $unknown->{stderr}, qr/Unknown\s+overnet-irc-server\s+command:\s+not-a-command/mx,
  'unknown command reports the bad command';
like $unknown->{stderr}, qr/Usage:/mx, 'unknown command prints usage';

done_testing;

sub _run {
  my (@args) = @_;
  my $command = join q{ }, map { _shell_quote($_) } ($^X, $script, @args);
  my $stdout  = qx{$command 2>/tmp/overnet-irc-main-cli-stderr.$$};
  my $exit    = $? >> 8;
  my $stderr  = _slurp("/tmp/overnet-irc-main-cli-stderr.$$");
  unlink "/tmp/overnet-irc-main-cli-stderr.$$";

  return {
    exit   => $exit,
    stdout => $stdout,
    stderr => $stderr,
  };
}

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "open $path failed: $!";
  my $content = do { local $/ = undef; <$fh> };
  close $fh
    or die "close $path failed: $!";
  return $content;
}

sub _shell_quote {
  my ($value) = @_;
  $value =~ s/'/'"'"'/gmx;
  return "'$value'";
}
