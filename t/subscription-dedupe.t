use strictures 2;

use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;

use Overnet::Program::IRC::Authority::Coordinator;
use TestSubscriptionServer;

my $server = bless {
  suppress_subscription_event_ids => {},
  rendered_subscription_event_ids => {},
  sent_lines                      => [],
  },
  'TestSubscriptionServer';

my $event = {
  id      => 'a' x 64,
  content => '{}',
};

is(
  Overnet::Program::IRC::Authority::Coordinator::handle_subscription_event(
    $server,
    {
      item_type => 'event',
      data      => $event,
    },
  ),
  1,
  'first subscription event is rendered',
);

is(
  Overnet::Program::IRC::Authority::Coordinator::handle_subscription_event(
    $server,
    {
      item_type => 'event',
      data      => $event,
    },
  ),
  0,
  'duplicate subscription event id is ignored',
);

is($server->{sent_lines}, [[1, ':seven3 PRIVMSG #overnet :Hello']], 'duplicate event produced no second client line',);

my $origin_server = bless {
  suppress_subscription_event_ids      => {},
  subscription_event_origin_client_ids => {('b' x 64) => 1},
  rendered_subscription_event_ids      => {},
  rendered_subscription_event_id_order => [],
  render_client_ids                    => [1, 2],
  sent_lines                           => [],
  },
  'TestSubscriptionServer';

is(
  Overnet::Program::IRC::Authority::Coordinator::handle_subscription_event(
    $origin_server,
    {
      item_type => 'event',
      data      => {
        id      => 'b' x 64,
        content => '{}',
      },
    },
  ),
  1,
  'origin-tracked subscription event reports delivered recipients',
);

is(
  $origin_server->{sent_lines},
  [[2, ':seven3 PRIVMSG #overnet :Hello']],
  'originating client is excluded from subscription fanout',
);

done_testing;
