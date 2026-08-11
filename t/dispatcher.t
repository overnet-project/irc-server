use strictures 2;

use File::Spec;
use FindBin;
use Scalar::Util qw(isweak refaddr);
use Test2::V0;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Program::IRC::Dispatcher;
use TestIRCServer;

my $server = TestIRCServer->new->configure(
  adapter_config  => {authority_profile => q{}, network => 'overnet',},
  authority_relay => undef,
);
my $dispatcher = $server->_dispatcher;

isa_ok $dispatcher, ['Overnet::Program::IRC::Dispatcher'];
is refaddr($dispatcher->server), refaddr($server),                  'the dispatcher has one weak server dependency';
is refaddr($dispatcher->parser), refaddr($server->_message_parser), 'the dispatcher shares the server parser';
ok isweak($dispatcher->{server}), 'the dispatcher cannot keep its owning server alive';

$server->add_client(1);
is $dispatcher->dispatch_line(1, 'PING token'), 1,               'connection commands dispatch before registration';
is $server->lines_for(1),                       ['PONG :token'], 'the selected connection handler runs';

$server->clear_sent_lines;
is $dispatcher->dispatch_line(1, 'PRIVMSG bob :hello'), 1, 'registered-only commands are rejected before registration';
like $server->lines_for(1)->[0], qr/\ 451\ /mxs, 'the registration-phase response is preserved';

$server->{clients}{1}{registered} = 1;
$server->clear_sent_lines;
is $dispatcher->dispatch_line(1, 'FROBNICATE'), 1, 'unknown registered commands are handled';
like $server->lines_for(1)->[0], qr/\ 421\ /mxs, 'the unknown-command response is preserved';

done_testing;
