use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-irc-proxy.pl');

ok -f $script, 'proxy script exists'
  or bail_out('overnet-irc-proxy.pl is required');

my $output = qx{$^X "$script" --help 2>&1};
my $exit   = $? >> 8;

is $exit, 0, '--help exits successfully';
like $output, qr/overnet-irc-proxy\.pl\ \[options\]/mx, 'usage names the proxy script';
like $output, qr/--listen-port\ PORT/mx,                  'usage documents the local listen port';
like $output, qr/--server-host\ HOST/mx,                  'usage documents the upstream server host';
like $output, qr/--server-tls/mx,                         'usage documents upstream TLS';
like $output, qr/--auth-sock\ PATH/mx,                    'usage documents auth-agent socket override';
like $output, qr/--auto-delegate/mx,                      'usage documents auto-delegation';
like $output, qr/SASL\ NOSTR/mx,                          'usage explains hidden SASL NOSTR auth';
like $output, qr/normal\ IRC\ client/mx,                  'usage explains the client-facing purpose';

done_testing;
