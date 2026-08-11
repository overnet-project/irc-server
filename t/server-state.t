use strictures 2;

use File::Spec;
use FindBin;
use Scalar::Util qw(refaddr);
use Test2::V0;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Program::IRC::State;
use TestIRCServer;

subtest 'the server aliases the state-owned indexes' => sub {
  my $server = TestIRCServer->new;

  is refaddr($server->{clients}),  refaddr($server->_state->clients),  'clients have one backing hash';
  is refaddr($server->{channels}), refaddr($server->_state->channels), 'channels have one backing hash';
  is refaddr($server->{nick_to_client_id}), refaddr($server->_state->nick_to_client_id),
    'the nick index has one backing hash';
};

my $state = Overnet::Program::IRC::State->new;
$state->clients->{1} = {nick => 'Alice', joined_channels => {},};
$state->clients->{2} = {nick => 'Bob',   joined_channels => {},};

subtest 'RFC 1459 names and indexes have one owner' => sub {
  is $state->irc_casefold('A[]\\^Z'), 'a{}|~z', 'RFC 1459 case folding is preserved';
  is $state->nick_key('ALICE'),       'alice',  'nick keys are case folded';
  ok $state->is_channel_name('#Engineering'), 'a channel name is recognized';
  ok !$state->is_channel_name(',bad'),        'an invalid channel is rejected';
  ok $state->is_nick_name('Alice'),           'a nick is recognized';
  ok !$state->is_nick_name('#channel'),       'a channel is not a nick';

  ok $state->assign_client_nick(1, 'Alice'),                'a known client can claim a nick';
  ok $state->nick_in_use('alice'),                          'the index uses IRC case mapping';
  ok !$state->nick_in_use('ALICE', exclude_client_id => 1), 'the owner can be excluded';
  is $state->canonical_current_nick('ALICE'),  'Alice',              'the current presentation is retained';
  is $state->client_for_current_nick('alice'), $state->clients->{1}, 'nick lookup returns the client';
  ok !$state->assign_client_nick(99, 'ghost'), 'an unknown client cannot claim a nick';
  ok $state->release_client_nick(1),           'the owner can release its nick';
  ok !$state->nick_in_use('alice'),            'release removes the index entry';
};

subtest 'channel membership presentation is isolated from transport logic' => sub {
  my $channel       = '#Engineering';
  my $channel_state = $state->channel_state($channel);
  is $channel_state->{channel_name},                 $channel, 'the first channel spelling is canonical';
  is $state->canonical_channel_name('#engineering'), $channel, 'case variants resolve to that spelling';

  my $channel_key = $state->channel_key($channel);
  $state->clients->{1}{joined_channels}{$channel_key} = $channel;
  is $state->client_joined_channel_name($state->clients->{1}, '#ENGINEERING'), $channel,
    'joined channels use the same index';

  is $state->add_visible_nick($channel, 'Alice'),    1,         'a visible nick is added';
  is $state->add_visible_nick($channel, 'ALICE'),    2,         'case variants share a reference count';
  is [$state->visible_nicks_for_channel($channel)],  ['ALICE'], 'the latest presentation is retained';
  is $state->remove_visible_nick($channel, 'alice'), 1,         'one observation is removed';
  is [$state->visible_nicks_for_channel($channel)],  ['ALICE'], 'one observation remains';
  is $state->rename_visible_nick($channel, old_nick => 'Alice', new_nick => 'Alicia'), 1,
    'the remaining observation can be renamed';
  is [$state->visible_nicks_for_channel($channel)], ['Alicia'], 'the renamed nick is visible';

  is $state->add_visible_nick(',bad', 'x'),        0, 'invalid channels do not create state';
  is $state->remove_visible_nick('#unknown', 'x'), 0, 'unknown channels remain absent';
};

done_testing;
