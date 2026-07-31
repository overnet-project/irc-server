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

# The walkthrough a person actually follows. Before it existed the README began
# at "run the agent with this config file" -- and producing that config was the
# step nobody could complete, because the scope derivation, the program id and
# the need for two policies were all undocumented. Each command below is load
# bearing: drop one and the reader is stranded at exactly that point.
like $content, qr/overnet-irc-server\ keygen/mx, 'README tells the reader how to create the identity they sign with';
like $content, qr/overnet-irc-server\ auth\ init/mx,   'README tells the reader how to produce the auth-agent config';
like $content, qr/--server-name/mx,                    'README shows the server name the scope is derived from';
like $content, qr/--network/mx,                        'README shows the network the scope is derived from';
like $content, qr{/connect\ 127[.]0[.]0[.]1\ 16668}mx, 'README shows the literal client command to reach the proxy';
like $content, qr/weechat/imx,                         'README covers more than one IRC client';
like $content, qr/policy-grant/mx, 'README explains the failure a mismatched config produces and how to fix it';
like $content, qr/one\ client\ connection\ at\ a\ time/mx, 'README discloses that the proxy serves a single client';

like $content, qr/OVERNET_AUTH_SOCK/mx,                'README documents OVERNET_AUTH_SOCK for auth-agent discovery';
like $content, qr/--auth-sock/mx,                      'README documents the explicit auth socket override';
like $content, qr/overnet-irc-server\ auth\ auth/mx,   'README documents the IRC auth helper';
like $content, qr/overnet-irc-server\ auth\ bridge/mx, 'README documents bridge mode';
like $content, qr/overnet-irc-server\ proxy/mx,        'README documents the local IRC proxy';
like $content, qr/--auto-delegate/mx,                  'README documents proxy auto-delegation';
like $content, qr/stdin/imx,                           'README documents stdin usage for bridge mode';
like $content, qr/SASL/imx,                            'README documents SASL auth flow';
like $content, qr/AUTHENTICATE/mx,                     'README documents AUTHENTICATE bridge usage';
like $content, qr/overnet-auth-agent\.pl\ --config-file/mx,
  'README documents starting the auth-agent daemon before IRC auth';

done_testing;
