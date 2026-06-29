use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

my @scripts = (
  'bin/overnet-irc-auth.pl',            'bin/overnet-irc-authority-relay-service.pl',
  'bin/overnet-irc-authority-relay.pl', 'bin/overnet-irc-chat-client.pl',
  'bin/overnet-irc-local-server.pl',    'bin/overnet-irc-server.pl',
  'bin/overnet-irc-service.pl',
);

plan tests => scalar @scripts;

for my $script (@scripts) {
  my $path = File::Spec->catfile($FindBin::Bin, '..', split m{/}mx, $script);
  my $ok   = system($^X, '-c', $path) == 0;
  ok $ok, "$script compiles";
}
