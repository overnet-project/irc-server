use strictures 2;

use Test2::V0;

use Overnet::Program::IRC::Server;

pipe(my $reader, my $writer)
  or die "pipe failed: $!";

my $server = Overnet::Program::IRC::Server->new;
$server->{clients}{'client-1'} = {
  id           => 'client-1',
  socket       => $writer,
  capabilities => {},
};

my $wide_marker = chr(0x1f702);

ok(
  $server->_send_client_line('client-1', ':seven3 PRIVMSG #overnet :hello kestrel ' . $wide_marker),
  'wide-character IRC line is written',
);

my $payload = '';
sysread($reader, $payload, 1024);

is(
  unpack('H*', $payload),
  unpack('H*', ":seven3 PRIVMSG #overnet :hello kestrel ") . 'f09f9c82' . unpack('H*', "\r\n"),
  'IRC line is encoded as UTF-8 bytes before syswrite',
);

subtest 'invalid fields suppress the whole line without exposing content' => sub {
  my @warnings;
  local $SIG{__WARN__} = sub { push @warnings, @_ };
  for my $text ("secret\r\nPRIVMSG bob :injected", "secret\0body", "secret\nbody") {
    is $server->_send_client_line('client-1', ':alice PRIVMSG #overnet :' . $text), 0,
      'raw invalid output is suppressed';
    is Overnet::Program::IRC::Renderer::server_notice_line(server_name => 'server', nick => 'alice', text => $text),
      undef, 'renderer refuses forbidden trailing characters';
  }
  is Overnet::Program::IRC::Renderer::no_such_channel_line(server_name => 'server', nick => 'alice', channel => '#room bob'),
    undef, 'a middle field cannot inject another parameter';
  is Overnet::Program::IRC::Renderer::server_notice_line(server_name => 'server NOTICE', nick => 'alice', text => 'hi'),
    undef, 'a prefix cannot inject another command';
  is Overnet::Program::IRC::Server::_channel_text_line('PRIVMSG', 'alice!user@host', '#room', 'hello'),
    undef, 'an external nick cannot supply a full prefix';
  ok @warnings, 'render failure is reported locally';
  unlike join('', @warnings), qr/secret|injected/, 'diagnostics contain no message content';
};

subtest 'renderer validates numeric fields, prefix components and format arity' => sub {
  my @warnings;
  local $SIG{__WARN__} = sub { push @warnings, @_ };
  for my $arguments (
    ['%s', 'PING', 'extra'],
    [':%s 001 %s', 'server'],
    [':%s 001 %s', 'server:injected', 'alice'],
    [':%s 001 %s', 'server@host', 'alice'],
    [':%s 001 %s', 'server!user', 'alice'],
    ['PING :%d', '1 extra'],
    ['PING :%d', undef],
    ['12BAD %s', 'field'],
  ) {
    is Overnet::Program::IRC::Renderer::format_line(@{$arguments}), undef,
      'an invalid renderer input suppresses the complete output';
  }
  is Overnet::Program::IRC::Renderer::format_line('PING :%d', 0), 'PING :0',
    'zero remains a valid numeric argument';
  ok @warnings, 'invalid rendering emits local diagnostics';
};

done_testing;
