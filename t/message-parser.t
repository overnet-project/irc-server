use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

use lib File::Spec->catdir($FindBin::Bin, '..', 'lib');

use Overnet::Program::IRC::MessageParser;

my $parser = Overnet::Program::IRC::MessageParser->new;

is $parser->parse(q{}),                undef, 'an empty line parses to nothing';
is $parser->parse(':nick!user@host '), undef, 'a prefix without a command parses to nothing';
is $parser->parse('@a=b '),            undef, 'tags without a command parse to nothing';

is $parser->parse('PRIVMSG #overnet :hello there'),
  {
  raw_line => 'PRIVMSG #overnet :hello there',
  command  => 'PRIVMSG',
  params   => ['#overnet', 'hello there'],
  },
  'a command and trailing parameter are parsed';

is $parser->parse('@time=now;flag;empty= :nick!user@host privmsg #overnet :Hi'),
  {
  raw_line    => '@time=now;flag;empty= :nick!user@host privmsg #overnet :Hi',
  tags        => {time => 'now', flag => q{}, empty => q{},},
  prefix      => 'nick!user@host',
  prefix_nick => 'nick',
  prefix_user => 'user',
  prefix_host => 'host',
  command     => 'PRIVMSG',
  params      => ['#overnet', 'Hi'],
  },
  'tags, user prefixes, and command case are normalized';

is $parser->parse(':upstream.server 001 alice :hi')->{prefix_nick}, 'upstream.server',
  'a server prefix remains available through prefix_nick';
is $parser->parse('PING   token  ')->{params}, ['token'], 'extra parameter whitespace is ignored';
is $parser->parse_tags('=v;;a=b'), {a => 'b'}, 'nameless tag entries are skipped';

done_testing;
