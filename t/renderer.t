use strictures 2;

use Test2::V0;

use Overnet::Program::IRC::Renderer;

my %common = (
  server_name => 'overnet.irc.local',
  nick        => 'alice',
);

subtest 'authenticate_payload_lines chunks payloads into 400-byte AUTHENTICATE lines' => sub {
  is Overnet::Program::IRC::Renderer::authenticate_payload_lines(payload => 'abc',), ['AUTHENTICATE abc',],
    'a short payload renders as a single AUTHENTICATE line';

  is Overnet::Program::IRC::Renderer::authenticate_payload_lines(), ['AUTHENTICATE +',],
    'a missing payload renders the empty-payload marker';

  is Overnet::Program::IRC::Renderer::authenticate_payload_lines(payload => q{},), ['AUTHENTICATE +',],
    'an empty payload renders the empty-payload marker';

  is Overnet::Program::IRC::Renderer::authenticate_payload_lines(payload => ('a' x 400),),
    ['AUTHENTICATE ' . ('a' x 400),], 'a payload of exactly 400 bytes stays on one line';

  is Overnet::Program::IRC::Renderer::authenticate_payload_lines(payload => ('a' x 400) . 'b',),
    ['AUTHENTICATE ' . ('a' x 400), 'AUTHENTICATE b',], 'a payload of 401 bytes splits into two lines';

  is Overnet::Program::IRC::Renderer::authenticate_payload_lines(payload => ('a' x 400) . ('b' x 400),),
    ['AUTHENTICATE ' . ('a' x 400), 'AUTHENTICATE ' . ('b' x 400),],
    'a payload of exactly 800 bytes splits into two full lines';

  is Overnet::Program::IRC::Renderer::authenticate_payload_lines(payload => ('a' x 400) . ('b' x 400) . 'c',),
    ['AUTHENTICATE ' . ('a' x 400), 'AUTHENTICATE ' . ('b' x 400), 'AUTHENTICATE c',],
    'a payload beyond 800 bytes keeps chunking';
};

subtest 'SASL result numerics' => sub {
  is Overnet::Program::IRC::Renderer::sasl_success_line(%common,),
    ':overnet.irc.local 903 alice :SASL authentication successful', 'renderer formats SASL success';

  is Overnet::Program::IRC::Renderer::sasl_fail_line(%common,),
    ':overnet.irc.local 904 alice :SASL authentication failed', 'renderer formats SASL failure';
};

subtest 'registration and command numerics' => sub {
  is Overnet::Program::IRC::Renderer::unknown_command_line(%common, command => 'FROB',),
    ':overnet.irc.local 421 alice FROB :Unknown command', 'renderer formats unknown-command replies';

  is Overnet::Program::IRC::Renderer::registration_prelude_lines(
    %common, isupport_tokens => 'CASEMAPPING=rfc1459 CHANTYPES=#& NETWORK=overnet',
    ),
    [
    ':overnet.irc.local 001 alice :Welcome to Overnet IRC',
    ':overnet.irc.local 005 alice CASEMAPPING=rfc1459 CHANTYPES=#& NETWORK=overnet :are supported by this server',
    ':overnet.irc.local 422 alice :MOTD File is missing',
    ],
    'renderer formats the registration prelude';

  is Overnet::Program::IRC::Renderer::nonickname_given_line(%common,),
    ':overnet.irc.local 431 alice :No nickname given', 'renderer formats no-nickname-given replies';

  is Overnet::Program::IRC::Renderer::not_registered_line(server_name => 'overnet.irc.local',),
    ':overnet.irc.local 451 * :You have not registered', 'renderer formats not-registered replies';

  is Overnet::Program::IRC::Renderer::need_more_params_line(%common, command => 'JOIN',),
    ':overnet.irc.local 461 alice JOIN :Not enough parameters', 'renderer formats need-more-params replies';

  is Overnet::Program::IRC::Renderer::server_notice_line(%common, text => 'maintenance window soon',),
    ':overnet.irc.local NOTICE alice :maintenance window soon', 'renderer formats server notices';

  is Overnet::Program::IRC::Renderer::nick_in_use_line(%common, attempted_nick => 'Alice',),
    ':overnet.irc.local 433 alice Alice :Nickname is already in use', 'renderer formats nick-in-use replies';
};

subtest 'account_notify_line presents the account or the logout marker' => sub {
  my %identity = (
    nick     => 'bob',
    username => 'bob',
    host     => '203.0.113.7',
  );

  is Overnet::Program::IRC::Renderer::account_notify_line(%identity, account => 'bob-account',),
    ':bob!bob@203.0.113.7 ACCOUNT bob-account', 'a usable account name is presented as-is';

  is Overnet::Program::IRC::Renderer::account_notify_line(%identity, account => undef,),
    ':bob!bob@203.0.113.7 ACCOUNT *', 'an undefined account renders the logout marker';

  is Overnet::Program::IRC::Renderer::account_notify_line(%identity, account => q{},),
    ':bob!bob@203.0.113.7 ACCOUNT *', 'an empty account renders the logout marker';

  is Overnet::Program::IRC::Renderer::account_notify_line(%identity, account => ['not', 'a', 'string'],),
    ':bob!bob@203.0.113.7 ACCOUNT *', 'a reference account renders the logout marker';
};

subtest 'target and channel error numerics' => sub {
  is Overnet::Program::IRC::Renderer::no_such_nick_line(%common, target_nick => 'ghost',),
    ':overnet.irc.local 401 alice ghost :No such nick/channel', 'renderer formats no-such-nick replies';

  is Overnet::Program::IRC::Renderer::no_such_channel_line(%common, channel => '#missing',),
    ':overnet.irc.local 403 alice #missing :No such channel', 'renderer formats no-such-channel replies';

  is Overnet::Program::IRC::Renderer::not_on_channel_line(%common, channel => '#overnet',),
    ':overnet.irc.local 442 alice #overnet :You\'re not on that channel', 'renderer formats not-on-channel replies';

  is Overnet::Program::IRC::Renderer::cannot_send_to_channel_line(%common, channel => '#overnet',),
    ':overnet.irc.local 404 alice #overnet :Cannot send to channel', 'renderer formats cannot-send replies';

  is Overnet::Program::IRC::Renderer::chan_op_privs_needed_line(%common, channel => '#overnet',),
    ':overnet.irc.local 482 alice #overnet :You\'re not channel operator', 'renderer formats chan-op-needed replies';
};

subtest 'cannot_join_channel_line selects the numeric from the rejection reason' => sub {
  my %join = (%common, channel => '#overnet',);

  is Overnet::Program::IRC::Renderer::cannot_join_channel_line(%join,),
    ':overnet.irc.local 473 alice #overnet :Cannot join channel', 'a missing reason uses 473 without a suffix';

  is Overnet::Program::IRC::Renderer::cannot_join_channel_line(%join, reason => q{},),
    ':overnet.irc.local 473 alice #overnet :Cannot join channel', 'an empty reason uses 473 without a suffix';

  is Overnet::Program::IRC::Renderer::cannot_join_channel_line(%join, reason => '+i',),
    ':overnet.irc.local 473 alice #overnet :Cannot join channel (+i)', 'invite-only rejections use 473';

  is Overnet::Program::IRC::Renderer::cannot_join_channel_line(%join, reason => '+b',),
    ':overnet.irc.local 474 alice #overnet :Cannot join channel (+b)', 'ban rejections use 474';

  is Overnet::Program::IRC::Renderer::cannot_join_channel_line(%join, reason => '+k',),
    ':overnet.irc.local 475 alice #overnet :Cannot join channel (+k)', 'key rejections use 475';

  is Overnet::Program::IRC::Renderer::cannot_join_channel_line(%join, reason => '+l',),
    ':overnet.irc.local 471 alice #overnet :Cannot join channel (+l)', 'limit rejections use 471';
};

subtest 'ban, exception, and invite-exception list numerics' => sub {
  my %chan = (%common, channel => '#overnet',);

  is Overnet::Program::IRC::Renderer::ban_list_entry_line(%chan, ban_mask => '*!*@example.test',),
    ':overnet.irc.local 367 alice #overnet *!*@example.test overnet.irc.local 0', 'renderer formats ban-list entries';

  is Overnet::Program::IRC::Renderer::end_of_ban_list_line(%chan,),
    ':overnet.irc.local 368 alice #overnet :End of channel ban list', 'renderer formats end-of-ban-list';

  is Overnet::Program::IRC::Renderer::exception_list_entry_line(%chan, exception_mask => '*!*@friend.test',),
    ':overnet.irc.local 348 alice #overnet *!*@friend.test overnet.irc.local 0',
    'renderer formats exception-list entries';

  is Overnet::Program::IRC::Renderer::end_of_exception_list_line(%chan,),
    ':overnet.irc.local 349 alice #overnet :End of channel exception list', 'renderer formats end-of-exception-list';

  is Overnet::Program::IRC::Renderer::invite_exception_list_entry_line(%chan, invite_exception_mask => '*!*@vip.test',),
    ':overnet.irc.local 346 alice #overnet *!*@vip.test overnet.irc.local 0',
    'renderer formats invite-exception entries';

  is Overnet::Program::IRC::Renderer::end_of_invite_exception_list_line(%chan,),
    ':overnet.irc.local 347 alice #overnet :End of channel invite exception list',
    'renderer formats end-of-invite-exception-list';
};

subtest 'invite and authoritative invite numerics' => sub {
  my %chan = (%common, channel => '#overnet',);

  is Overnet::Program::IRC::Renderer::inviting_line(%chan, target_nick => 'bob',),
    ':overnet.irc.local 341 alice bob #overnet', 'renderer formats inviting confirmations';

  is Overnet::Program::IRC::Renderer::authoritative_invite_list_entry_line(
    %chan,
    target_pubkey => 'deadbeef' x 8,
    invite_code   => 'invite-code-1',
    ),
    ':overnet.irc.local 336 alice #overnet ' . ('deadbeef' x 8) . ' invite-code-1',
    'renderer formats authoritative invite entries';

  is Overnet::Program::IRC::Renderer::end_of_authoritative_invite_list_line(%chan,),
    ':overnet.irc.local 337 alice #overnet :End of authoritative invite list',
    'renderer formats end-of-authoritative-invite-list';

  is Overnet::Program::IRC::Renderer::authoritative_join_request_list_entry_line(
    %chan,
    requester_pubkey => 'cafef00d' x 8,
    actor_mask       => 'op!op@overnet.irc.local',
    ),
    ':overnet.irc.local 338 alice #overnet ' . ('cafef00d' x 8) . ' op!op@overnet.irc.local',
    'a join-request entry presents the actor mask when one is known';

  is Overnet::Program::IRC::Renderer::authoritative_join_request_list_entry_line(
    %chan, requester_pubkey => 'cafef00d' x 8,
    ),
    ':overnet.irc.local 338 alice #overnet ' . ('cafef00d' x 8) . ' *',
    'a join-request entry without an actor mask presents the placeholder';

  is Overnet::Program::IRC::Renderer::authoritative_join_request_list_entry_line(
    %chan,
    requester_pubkey => 'cafef00d' x 8,
    actor_mask       => q{},
    ),
    ':overnet.irc.local 338 alice #overnet ' . ('cafef00d' x 8) . ' *',
    'a join-request entry with an empty actor mask presents the placeholder';

  is Overnet::Program::IRC::Renderer::end_of_authoritative_join_request_list_line(%chan,),
    ':overnet.irc.local 339 alice #overnet :End of authoritative join request list',
    'renderer formats end-of-authoritative-join-request-list';
};

subtest 'channel_mode_is_line appends only usable mode arguments' => sub {
  my %chan = (%common, channel => '#overnet',);

  is Overnet::Program::IRC::Renderer::channel_mode_is_line(
    %chan,
    channel_modes => '+ntkl',
    mode_args     => ['sekrit', undef, q{}, ['not-a-string'], '10',],
    ),
    ':overnet.irc.local 324 alice #overnet +ntkl sekrit 10',
    'undef, empty, and reference mode arguments are dropped from the suffix';

  is Overnet::Program::IRC::Renderer::channel_mode_is_line(%chan, channel_modes => '+nt',),
    ':overnet.irc.local 324 alice #overnet +nt', 'missing mode arguments render no suffix';

  is Overnet::Program::IRC::Renderer::channel_mode_is_line(%chan, channel_modes => '+nt', mode_args => [],),
    ':overnet.irc.local 324 alice #overnet +nt', 'an empty mode-argument list renders no suffix';
};

subtest 'user and server status numerics' => sub {
  is Overnet::Program::IRC::Renderer::user_mode_is_line(%common,), ':overnet.irc.local 221 alice +',
    'renderer formats user-mode replies';

  is Overnet::Program::IRC::Renderer::lusers_reply_lines(
    %common,
    registered_users  => 3,
    channels          => 2,
    connected_clients => 4,
    ),
    [
    ':overnet.irc.local 251 alice :There are 3 users and 0 services on 1 server',
    ':overnet.irc.local 252 alice 0 :operator(s) online',
    ':overnet.irc.local 253 alice 0 :unknown connection(s)',
    ':overnet.irc.local 254 alice 2 :channels formed',
    ':overnet.irc.local 255 alice :I have 4 clients and 1 server',
    ],
    'renderer formats the LUSERS reply block';
};

subtest 'list_reply_lines renders one 322 per entry between the list markers' => sub {
  is Overnet::Program::IRC::Renderer::list_reply_lines(
    %common,
    entries => [
      {
        channel       => '#overnet',
        visible_users => 2,
        topic         => 'Authoritative topic',
      },
      {
        channel       => '#quiet',
        visible_users => 0,
        topic         => q{},
      },
    ],
    ),
    [
    ':overnet.irc.local 321 alice Channel :Users Name',
    ':overnet.irc.local 322 alice #overnet 2 :Authoritative topic',
    ':overnet.irc.local 322 alice #quiet 0 :',
    ':overnet.irc.local 323 alice :End of /LIST',
    ],
    'renderer formats a populated LIST response';

  is Overnet::Program::IRC::Renderer::list_reply_lines(%common,),
    [':overnet.irc.local 321 alice Channel :Users Name', ':overnet.irc.local 323 alice :End of /LIST',],
    'renderer formats an empty LIST response';
};

subtest 'topic numerics' => sub {
  is Overnet::Program::IRC::Renderer::topic_is_line(%common, channel => '#overnet', topic => 'Authoritative topic',),
    ':overnet.irc.local 332 alice #overnet :Authoritative topic', 'renderer formats topic replies';

  is Overnet::Program::IRC::Renderer::no_topic_line(%common, channel => '#overnet',),
    ':overnet.irc.local 331 alice #overnet :No topic is set', 'renderer formats no-topic replies';
};

subtest 'userhost_line joins the reply entries' => sub {
  is Overnet::Program::IRC::Renderer::userhost_line(%common, entries => ['alice=+alice@host-a', 'bob=+bob@host-b',],),
    ':overnet.irc.local 302 alice :alice=+alice@host-a bob=+bob@host-b', 'renderer formats populated USERHOST replies';

  is Overnet::Program::IRC::Renderer::userhost_line(%common,), ':overnet.irc.local 302 alice :',
    'renderer formats empty USERHOST replies';
};

subtest 'who_list_lines renders one 352 per entry before the end marker' => sub {
  is Overnet::Program::IRC::Renderer::who_list_lines(
    %common,
    channel => '#overnet',
    entries => [
      {
        username => 'bob',
        host     => 'host-b',
        nick     => 'bob',
        realname => 'Bob Example',
      },
    ],
    ),
    [
    ':overnet.irc.local 352 alice #overnet bob host-b overnet.irc.local bob H :0 Bob Example',
    ':overnet.irc.local 315 alice #overnet :End of /WHO list.',
    ],
    'renderer formats a populated WHO response';

  is Overnet::Program::IRC::Renderer::who_list_lines(%common, channel => '#overnet',),
    [':overnet.irc.local 315 alice #overnet :End of /WHO list.',], 'renderer formats an empty WHO response';
};

subtest 'whois_reply_lines includes the account numeric only for usable accounts' => sub {
  my %entry = (
    nick     => 'bob',
    username => 'bob',
    host     => 'host-b',
    realname => 'Bob Example',
  );
  my %whois = (%common, server_description => 'Overnet IRC bridge',);

  is Overnet::Program::IRC::Renderer::whois_reply_lines(%whois, entry => {%entry, account => 'bob-account',},),
    [
    ':overnet.irc.local 311 alice bob bob host-b * :Bob Example',
    ':overnet.irc.local 330 alice bob bob-account :is logged in as',
    ':overnet.irc.local 312 alice bob overnet.irc.local :Overnet IRC bridge',
    ':overnet.irc.local 318 alice bob :End of /WHOIS list.',
    ],
    'a usable account adds the 330 numeric';

  is Overnet::Program::IRC::Renderer::whois_reply_lines(%whois, entry => {%entry},),
    [
    ':overnet.irc.local 311 alice bob bob host-b * :Bob Example',
    ':overnet.irc.local 312 alice bob overnet.irc.local :Overnet IRC bridge',
    ':overnet.irc.local 318 alice bob :End of /WHOIS list.',
    ],
    'a missing account omits the 330 numeric';

  is Overnet::Program::IRC::Renderer::whois_reply_lines(%whois, entry => {%entry, account => q{},},),
    [
    ':overnet.irc.local 311 alice bob bob host-b * :Bob Example',
    ':overnet.irc.local 312 alice bob overnet.irc.local :Overnet IRC bridge',
    ':overnet.irc.local 318 alice bob :End of /WHOIS list.',
    ],
    'an empty account omits the 330 numeric';

  is Overnet::Program::IRC::Renderer::whois_reply_lines(%whois, entry => {%entry, account => {},},),
    [
    ':overnet.irc.local 311 alice bob bob host-b * :Bob Example',
    ':overnet.irc.local 312 alice bob overnet.irc.local :Overnet IRC bridge',
    ':overnet.irc.local 318 alice bob :End of /WHOIS list.',
    ],
    'a reference account omits the 330 numeric';
};

subtest 'names_list_lines joins names into the 353 numeric' => sub {
  is Overnet::Program::IRC::Renderer::names_list_lines(%common, channel => '#overnet', names => ['@alice', '+bob',],),
    [
    ':overnet.irc.local 353 alice = #overnet :@alice +bob',
    ':overnet.irc.local 366 alice #overnet :End of /NAMES list.',
    ],
    'renderer formats a populated NAMES response';

  is Overnet::Program::IRC::Renderer::names_list_lines(%common, channel => '#overnet',),
    [
    ':overnet.irc.local 353 alice = #overnet :',
    ':overnet.irc.local 366 alice #overnet :End of /NAMES list.',
    ],
    'renderer formats an empty NAMES response';
};

done_testing;
