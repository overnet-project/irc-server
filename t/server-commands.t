use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Core::Nostr;
use Overnet::Program::IRC::Server;
use TestIRCServer;

my $channel = '#overnet';

sub _server {
  my (%overrides) = @_;
  my $server = TestIRCServer->new;
  $server->configure(
    adapter_config => {
      authority_profile => q{},
      network           => 'overnet',
    },
    authority_relay => undef,
    %overrides,
  );
  $server->{signing_key}        = Overnet::Core::Nostr->generate_key;
  $server->{adapter_session_id} = 'adapter-session-1';
  return $server;
}

sub _lines {
  my ($server, $client_id) = @_;
  return join "\n", @{$server->lines_for($client_id)};
}

sub _register {
  my ($server, $client_id, $nick) = @_;
  $server->add_client($client_id);
  $server->_handle_client_line($client_id, "NICK $nick");
  $server->_handle_client_line($client_id, "USER $nick 0 * :$nick");
  return $server->{clients}{$client_id};
}

subtest 'clients register through NICK and USER' => sub {
  my $server = _server();
  is $server->_handle_client_line(99, 'NICK ghost'), 1, 'an unknown client is tolerated';

  $server->add_client(1);
  is $server->_handle_client_line(1, '   '), 1, 'an unparseable line is ignored';
  is $server->_handle_client_line(1, 'NICK'), 1, 'NICK without a nick is handled';
  like _lines($server, 1), qr/431/mxs, 'NICK without a nick reports no nickname given';

  is $server->_handle_client_line(1, 'USER alice 0'), 1, 'USER with too few params is handled';
  like _lines($server, 1), qr/461 .* USER/mxs, 'a short USER asks for more parameters';

  is $server->_handle_client_line(1, 'PRIVMSG bob :hi'), 1, 'a registered-only command before registration is handled';
  like _lines($server, 1), qr/451/mxs, 'the client is told it is not registered';

  is $server->_handle_client_line(1, 'FROBNICATE'), 1, 'an unknown command before registration is handled';
  like _lines($server, 1), qr/421 .* FROBNICATE/mxs, 'the unknown command is reported';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'NICK alice'), 1, 'NICK is accepted';
  is $server->_handle_client_line(1, 'NICK ALICE'), 1, 'a case-variant NICK for the same client is accepted';
  is $server->_handle_client_line(1, 'USER alice 0 * :Alice Example'), 1, 'USER completes registration';
  like _lines($server, 1), qr/001 .* Welcome|001/mxs, 'the registration prelude is sent';
  is $server->{clients}{1}{registered}, 1, 'the client is registered';
  is $server->{clients}{1}{realname}, 'Alice Example', 'the realname is stored';
  my ($dm) = grep { $_->{method} eq 'subscriptions.open' && $_->{params}{subscription_id} =~ /\Adm:/mxs }
    @{$server->requests};
  ok $dm, 'a DM subscription is opened at registration';

  is $server->_handle_client_line(1, 'USER alice 0 * :again'), 1, 'USER after registration is handled';
  is $server->{clients}{1}{realname}, 'Alice Example', 'USER after registration is a no-op';

  $server->add_client(2);
  $server->_handle_client_line(2, 'NICK alice');
  like _lines($server, 2), qr/433/mxs, 'an unregistered nick collision is reported';

  $server->_handle_client_line(2, 'NICK bob');
  $server->_handle_client_line(2, 'USER bob 0 * :Bob');
  $server->clear_sent_lines;
  is $server->_handle_client_line(2, 'NICK alice'), 1, 'a registered nick collision is handled';
  like _lines($server, 2), qr/433/mxs, 'the registered nick collision is reported';

  is $server->_handle_client_line(2, 'NICK bob'), 1, 'renaming to the current nick is handled';
  is $server->_handle_client_line(2, 'NICK ,bad'), 1, 'renaming to an unusable nick is handled';
};

subtest 'registered nick changes rename channels and notify watchers' => sub {
  my $server = _server();
  my $alice  = _register($server, 1, 'alice');
  my $bob    = _register($server, 2, 'bob');
  $server->_handle_client_line(1, "JOIN $channel");
  $server->_handle_client_line(2, "JOIN $channel");

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'NICK alicia'), 1, 'a registered rename is handled';
  like _lines($server, 2), qr/:alice\ NICK\ :alicia/mxs, 'channel members see the rename';
  is $alice->{nick}, 'alicia', 'the client nick is updated';
  my $channel_state = $server->{channels}{$server->_channel_key($channel)};
  ok $channel_state->{visible_nicks}{$server->_nick_key('alicia')}, 'the visible nick is renamed';
  ok !$channel_state->{visible_nicks}{$server->_nick_key('alice')}, 'the old visible nick is gone';
  ok $server->{nick_to_client_id}{$server->_nick_key('alicia')}, 'the nick table follows the rename';

  my $loner = _register($server, 3, 'carol');
  $server->clear_sent_lines;
  is $server->_handle_client_line(3, 'NICK caroline'), 1, 'a channel-less rename is handled';
  like _lines($server, 3), qr/:carol\ NICK\ :caroline/mxs, 'the renaming client hears its own rename';
};

subtest 'PING, QUIT, and unknown commands are answered' => sub {
  my $server = _server();
  my $alice  = _register($server, 1, 'alice');
  my $bob    = _register($server, 2, 'bob');
  $server->_handle_client_line(1, "JOIN $channel");
  $server->_handle_client_line(2, "JOIN $channel");

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'PING token-1'), 1, 'PING is handled';
  like _lines($server, 1), qr/\APONG\ :token-1\z/mxs, 'PING is answered with the token';
  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'PING'), 1, 'PING without a token is handled';
  like _lines($server, 1), qr/\APONG\ :\z/mxs, 'a tokenless PING is answered';

  is $server->_handle_client_line(1, 'FROBNICATE x'), 1, 'an unknown registered command is handled';
  like _lines($server, 1), qr/421 .* FROBNICATE/mxs, 'the unknown command is reported';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'QUIT :gone home'), 1, 'QUIT is handled';
  like _lines($server, 2), qr/:alice\ QUIT\ :gone\ home/mxs, 'channel members see the quit';
  ok !exists $server->{clients}{1}, 'the quitting client is removed';
  ok !$server->{nick_to_client_id}{$server->_nick_key('alice')}, 'the nick is released';
  my ($closed) = grep { $_->{method} eq 'subscriptions.close' } @{$server->requests};
  ok $closed, 'the DM subscription is closed on quit';
};

subtest 'OVERNETKEY stores and reports E2EE pubkeys' => sub {
  my $server = _server();
  my $alice  = _register($server, 1, 'alice');
  my $bob    = _register($server, 2, 'bob');

  is $server->_handle_client_line(1, 'OVERNETKEY SET ' . ('a' x 64)), 1, 'OVERNETKEY without the cap is handled';
  like _lines($server, 1), qr/requires\ CAP\ overnet-e2ee/mxs, 'the missing capability is reported';

  $alice->{capabilities}{'overnet-e2ee'} = 1;
  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'OVERNETKEY SET'), 1, 'OVERNETKEY without params is handled';
  like _lines($server, 1), qr/461 .* OVERNETKEY/mxs, 'missing params ask for more parameters';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'OVERNETKEY SET nothex'), 1, 'a malformed pubkey is handled';
  like _lines($server, 1), qr/requires\ a\ 64-character/mxs, 'the malformed pubkey is reported';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'OVERNETKEY SET ' . ('A' x 64)), 1, 'a valid pubkey is stored';
  is $alice->{e2ee_pubkey}, 'a' x 64, 'the pubkey is lowercased and stored';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'OVERNETKEY GET ghost'), 1, 'GET for an unknown nick is handled';
  like _lines($server, 1), qr/401/mxs, 'the unknown nick is reported';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'OVERNETKEY GET bob'), 1, 'GET for a keyless nick is handled';
  like _lines($server, 1), qr/OVERNETKEY\ GET\ bob\ [*]/mxs, 'a keyless nick reports an asterisk';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'OVERNETKEY GET alice'), 1, 'GET for a keyed nick is handled';
  like _lines($server, 1), qr/OVERNETKEY\ GET\ alice\ a{64}/mxs, 'the stored pubkey is reported';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'OVERNETKEY FROB x'), 1, 'an unknown subcommand is handled';
  like _lines($server, 1), qr/421 .* OVERNETKEY/mxs, 'the unknown subcommand is reported';
};

subtest 'USERHOST, WHO, WHOIS, NAMES, and LUSERS report presence' => sub {
  my $server = _server();
  my $alice  = _register($server, 1, 'alice');
  my $bob    = _register($server, 2, 'bob');
  $server->_handle_client_line(1, "JOIN $channel");
  $server->_handle_client_line(2, "JOIN $channel");

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'USERHOST'), 1, 'USERHOST without params is handled';
  like _lines($server, 1), qr/461 .* USERHOST/mxs, 'missing params ask for more parameters';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'USERHOST alice ALICE bob ghost ,bad'), 1, 'USERHOST is handled';
  my ($userhost) = grep { /302/mxs } @{$server->lines_for(1)};
  like $userhost, qr/alice=[+]/mxs, 'the reply includes the requesting nick';
  like $userhost, qr/bob=[+]/mxs,   'the reply includes other known nicks';
  unlike $userhost, qr/ghost/mxs, 'unknown nicks are omitted';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'WHO'), 1, 'WHO without params is handled';
  like _lines($server, 1), qr/461 .* WHO/mxs, 'missing params ask for more parameters';
  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'WHO nochannel'), 1, 'WHO for a non-channel is handled';
  like _lines($server, 1), qr/403/mxs, 'the non-channel target is reported';
  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'WHO #elsewhere'), 1, 'WHO for an unjoined channel is handled';
  like _lines($server, 1), qr/442/mxs, 'the unjoined channel is reported';
  $server->clear_sent_lines;
  is $server->_handle_client_line(1, "WHO $channel"), 1, 'WHO for a joined channel is handled';
  like _lines($server, 1), qr/352 .* bob/mxs, 'the WHO list includes the members';
  like _lines($server, 1), qr/315/mxs,        'the WHO list is terminated';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'WHOIS'), 1, 'WHOIS without params is handled';
  like _lines($server, 1), qr/461 .* WHOIS/mxs, 'missing params ask for more parameters';
  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'WHOIS ghost'), 1, 'WHOIS for an unknown nick is handled';
  like _lines($server, 1), qr/401/mxs, 'the unknown nick is reported';
  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'WHOIS bob'), 1, 'WHOIS for a known nick is handled';
  like _lines($server, 1), qr/311 .* bob/mxs, 'the WHOIS reply names the target';
  like _lines($server, 1), qr/318/mxs,        'the WHOIS reply is terminated';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'NAMES'), 1, 'NAMES without params is handled';
  like _lines($server, 1), qr/461 .* NAMES/mxs, 'missing params ask for more parameters';
  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'NAMES nochannel'), 1, 'NAMES for a non-channel is handled';
  like _lines($server, 1), qr/403/mxs, 'the non-channel target is reported';
  $server->clear_sent_lines;
  is $server->_handle_client_line(1, "NAMES $channel"), 1, 'NAMES for a channel is handled';
  like _lines($server, 1), qr/353 .* alice/mxs, 'the NAMES reply lists members';
  like _lines($server, 1), qr/366/mxs,          'the NAMES reply is terminated';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'LUSERS'), 1, 'LUSERS is handled';
  like _lines($server, 1), qr/251/mxs, 'the LUSERS reply reports the user counts';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, 'LIST'), 1, 'LIST dispatches through the registered handlers';
  like _lines($server, 1), qr/323/mxs, 'the LIST reply is terminated';

  $server->clear_sent_lines;
  is $server->_handle_client_line(1, "TOPIC $channel"), 1, 'TOPIC dispatches through the registered handlers';
  like _lines($server, 1), qr/331|332/mxs, 'the TOPIC reply reports the topic state';

  is $server->_handle_client_line(1, "PART $channel :bye"), 1, 'PART dispatches through the registered handlers';
  is $server->_handle_client_line(1, 'OVERNETAUTH'), 1, 'OVERNETAUTH dispatches through the registered handlers';
  is $server->_handle_client_line(1, 'OVERNETCHANNEL'), 1,
    'OVERNETCHANNEL dispatches through the registered handlers';
  is $server->_handle_client_line(1, "MODE $channel"), 1, 'MODE dispatches through the registered handlers';
  is $server->_handle_client_line(1, "KICK $channel bob"), 1, 'KICK dispatches through the registered handlers';
  is $server->_handle_client_line(1, "INVITE bob $channel"), 1,
    'INVITE dispatches through the registered handlers';
  is $server->_handle_client_line(1, 'PRIVMSG bob :hi'), 1, 'PRIVMSG dispatches through the registered handlers';
  is $server->_handle_client_line(1, 'NOTICE bob :hi'), 1, 'NOTICE dispatches through the registered handlers';
  is $server->_handle_client_line(1, 'CAP LS'), 1, 'CAP dispatches through the connection handlers';
  is $server->_handle_client_line(1, 'AUTHENTICATE NOSTR'), 1,
    'AUTHENTICATE dispatches through the connection handlers';
};

subtest 'IRC message parsing handles tags, prefixes, and malformed lines' => sub {
  my $server = _server();

  is $server->_parse_irc_message(q{}), undef, 'an empty line parses to nothing';
  is $server->_parse_irc_message(':nick!user@host '), undef, 'a prefix without a command parses to nothing';
  is $server->_parse_irc_message('@a=b '),            undef, 'tags without a command parse to nothing';

  my $plain = $server->_parse_irc_message('PRIVMSG #overnet :hello there');
  is $plain->{command}, 'PRIVMSG', 'the command is parsed';
  is $plain->{params}, ['#overnet', 'hello there'], 'the trailing parameter is preserved';

  my $tagged = $server->_parse_irc_message('@time=now;flag;empty= :nick!user@host privmsg #overnet :Hi');
  is $tagged->{command}, 'PRIVMSG', 'the command is upcased';
  is $tagged->{prefix},  'nick!user@host', 'the prefix is parsed';
  is $tagged->{tags}{time}, 'now', 'valued tags are parsed';
  is $tagged->{tags}{flag}, q{},   'bare tags default to an empty value';
  is $tagged->{tags}{empty}, q{},  'empty tag values stay empty';

  my $spaced = $server->_parse_irc_message('PING   token  ');
  is $spaced->{command}, 'PING',    'the command survives repeated separators';
  is $spaced->{params},  ['token'], 'parameters are split on runs of spaces';

  ok $server->_command_requires_registration('PRIVMSG'), 'PRIVMSG requires registration';
  ok !$server->_command_requires_registration('CAP'),    'CAP does not require registration';
  ok !$server->_command_requires_registration(undef),    'an undefined command does not require registration';
};

subtest 'outbound lines are decorated for capable clients' => sub {
  my $server = _server();
  my $alice  = _register($server, 1, 'alice');
  my $bob    = _register($server, 2, 'bob');
  $bob->{authority_pubkey} = 'b' x 64;

  my $plain = $server->_decorate_outbound_line_for_client($alice, ':bob PRIVMSG alice :hi');
  is $plain, ':bob PRIVMSG alice :hi', 'clients without caps get undecorated lines';

  $alice->{capabilities}{'server-time'}  = 1;
  $alice->{capabilities}{'account-tag'}  = 1;
  $alice->{capabilities}{'message-tags'} = 1;
  my $decorated = $server->_decorate_outbound_line_for_client($alice, ':bob PRIVMSG alice :hi');
  like $decorated, qr/\A@.*time=\d{4}/mxs, 'server-time adds a time tag';
  like $decorated, qr/account=b{64}/mxs,   'account-tag names the sender account';

  my $notice = $server->_decorate_outbound_line_for_client($alice, ':ghost PRIVMSG alice :hi');
  unlike $notice, qr/account=/mxs, 'unknown senders carry no account tag';

  my $numeric = $server->_decorate_outbound_line_for_client($alice, ':irc.example.test 001 alice :hi');
  unlike $numeric, qr/account=/mxs, 'server-sourced lines carry no account tag';

  is $server->_ircv3_server_time_tag(0), '1970-01-01T00:00:00.000Z', 'the time tag formats epoch zero';
};

done_testing;
