use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

my $readme = File::Spec->catfile($FindBin::Bin, '..', 'README.md');

ok -f $readme, 'README exists'
  or bail_out('README.md is required');

open my $fh, '<', $readme
  or die "open $readme failed: $!";
my $content = do { local $/ = undef; <$fh> };
close $fh
  or die "close $readme failed: $!";

like $content, qr/OVERNET_AUTH_SOCK/mx,            'README documents OVERNET_AUTH_SOCK for auth-agent discovery';
like $content, qr/--auth-sock/mx,                  'README documents the explicit auth socket override';
like $content, qr/overnet-irc-server\ auth\ auth/mx,   'README documents the IRC auth helper';
like $content, qr/overnet-irc-server\ auth\ bridge/mx, 'README documents bridge mode';
like $content, qr/overnet-irc-server\ proxy/mx,        'README documents the local IRC proxy';
like $content, qr/--auto-delegate/mx,              'README documents proxy auto-delegation';
like $content, qr/stdin/imx,                       'README documents stdin usage for bridge mode';
like $content, qr/SASL/imx,                        'README documents SASL auth flow';
like $content, qr/AUTHENTICATE/mx,                 'README documents AUTHENTICATE bridge usage';
like $content, qr/overnet-auth-agent\.pl\ --config-file/mx,
  'README documents starting the auth-agent daemon before IRC auth';

done_testing;
