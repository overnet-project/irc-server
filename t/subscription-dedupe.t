use strictures 2;

use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;

use Overnet::Program::IRC::Authority::Coordinator;
use TestSubscriptionServer;

sub _coordinator {
  my ($server) = @_;
  return Overnet::Program::IRC::Authority::Coordinator->new(server => $server,);
}

my $server = TestSubscriptionServer->new(
  suppress_subscription_event_ids => {},
  rendered_subscription_event_ids => {},
  sent_lines                      => [],
);

my $event = {
  id      => 'a' x 64,
  content => '{}',
};

is(
  _coordinator($server)->handle_subscription_event(
    {
      item_type => 'event',
      data      => $event,
    },
  ),
  1,
  'first subscription event is rendered',
);

is(
  _coordinator($server)->handle_subscription_event(
    {
      item_type => 'event',
      data      => $event,
    },
  ),
  0,
  'duplicate subscription event id is ignored',
);

is($server->{sent_lines}, [[1, ':seven3 PRIVMSG #overnet :Hello']], 'duplicate event produced no second client line',);

my $origin_server = TestSubscriptionServer->new(
  suppress_subscription_event_ids      => {},
  subscription_event_origin_client_ids => {('b' x 64) => 1},
  rendered_subscription_event_ids      => {},
  rendered_subscription_event_id_order => [],
  render_client_ids                    => [1, 2],
  sent_lines                           => [],
);

is(
  _coordinator($origin_server)->handle_subscription_event(
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
