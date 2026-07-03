use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-irc-server');

ok -f $script, 'IRC command exists'
  or bail_out('overnet-irc-server is required');

my $output = qx{$^X "$script" auth --help 2>&1};
my $exit   = $? >> 8;

is $exit, 0, '--help exits successfully';
like $output, qr/overnet-irc-server\ auth\ bridge\ \[options\]/mx, 'usage includes bridge mode';
like $output, qr/--line\ IRC_NOTICE_LINE/mx,                   'usage documents explicit single-line bridge mode';
like $output, qr/stdin/imx,                                    'usage documents continuous stdin bridge mode';
like $output, qr/SASL/imx,                                     'usage documents SASL bridge support';
like $output, qr/AUTHENTICATE/mx,                              'usage documents AUTHENTICATE challenge handling';

done_testing;
