use strictures 2;

use Test2::V0;

use Overnet::Program::IRC::Server;

sub _server {
  my (%config) = @_;
  my $server = Overnet::Program::IRC::Server->new;
  $server->{config} = {
    server_name => 'overnet.irc.local',
    network     => 'overnet',
    %config,
  };
  return $server;
}

sub _host {
  my ($server, $peerhost) = @_;
  return $server->_presentational_host_for_client({peerhost => $peerhost});
}

subtest 'a peer IP is presented as a stable cloak, never the raw address' => sub {
  my $server = _server(cloak_secret => 'fixed-test-secret');

  my $cloak = _host($server, '203.0.113.7');
  like $cloak,   qr/\A[0-9a-f]{16}\.users\.overnet\z/mx, 'cloak has the expected synthetic host shape';
  unlike $cloak, qr/203\.0\.113\.7/mx,                   'cloak does not contain the raw IP';

  is _host($server, '203.0.113.7'), $cloak, 'the same IP always cloaks to the same host';
};

subtest 'different peer IPs cloak to different hosts' => sub {
  my $server = _server(cloak_secret => 'fixed-test-secret');
  isnt _host($server, '203.0.113.7'), _host($server, '198.51.100.9'), 'distinct IPs produce distinct cloaks';
};

subtest 'the cloak is keyed by the server cloak secret' => sub {
  my $one = _server(cloak_secret => 'secret-one');
  my $two = _server(cloak_secret => 'secret-two');
  isnt _host($one, '203.0.113.7'), _host($two, '203.0.113.7'),
    'the same IP cloaks differently under a different secret';
};

subtest 'an IPv6 peer address is cloaked as well' => sub {
  my $server = _server(cloak_secret => 'fixed-test-secret');
  my $cloak  = _host($server, '2001:db8::42');
  like $cloak,   qr/\A[0-9a-f]{16}\.users\.overnet\z/mx, 'IPv6 cloak has the synthetic host shape';
  unlike $cloak, qr/2001|db8/mx,                         'IPv6 cloak does not leak address fragments';
};

subtest 'a client without a peer address falls back to the default host' => sub {
  my $server  = _server(cloak_secret => 'fixed-test-secret');
  my $default = $server->_default_presentational_host;

  is $server->_presentational_host_for_client({}),               $default, 'missing peerhost uses the default host';
  is $server->_presentational_host_for_client({peerhost => ''}), $default, 'empty peerhost uses the default host';
  is $server->_presentational_host_for_client('not-a-hashref'),  $default, 'non-hashref client uses the default host';
};

subtest 'a generated secret still cloaks and hides the IP when none is configured' => sub {
  my $server = _server();
  my $cloak  = _host($server, '203.0.113.7');
  like $cloak,   qr/\A[0-9a-f]{16}\.users\.overnet\z/mx, 'generated-secret cloak has the synthetic host shape';
  unlike $cloak, qr/203\.0\.113\.7/mx,                   'generated-secret cloak does not contain the raw IP';
  is _host($server, '203.0.113.7'), $cloak, 'generated secret is stable within the process';
};

done_testing;
