use strictures 2;

use Test2::V0;

for my $module (
  qw(
  Overnet::Program::IRC::Authority::Coordinator
  Overnet::Program::IRC::Command::Auth
  Overnet::Program::IRC::Command::Channel
  Overnet::Program::IRC::Proxy
  Overnet::Program::IRC::Renderer
  Overnet::Program::IRC::Server
  )
) {
  my $path = $module =~ s{::}{/}gr . '.pm';
  my $ok   = eval {
    require $path;
    1;
  };
  ok $ok, "$module loads"
    or diag $@;
}

my $server = Overnet::Program::IRC::Server->new({});
isa_ok $server, ['Overnet::Program::IRC::Server'], 'hashref constructor';

done_testing;
