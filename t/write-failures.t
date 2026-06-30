use strictures 2;

use Test2::V0;

use Overnet::Program::IRC::Script::ChatClient;
use Overnet::Program::IRC::Server;

subtest 'chat client write loop rejects zero-byte syswrite' => sub {
  tie *CHAT_ZERO_WRITE, 't::ZeroWriteHandle';
  my $client = bless {socket => \*CHAT_ZERO_WRITE}, 'Overnet::Program::IRC::Script::ChatClient';

  my $error = dies { $client->_send_line('PING :server') };

  like $error, qr/Failed\ to\ write\ IRC\ line/mx, 'zero-byte chat-client write is fatal';
};

subtest 'runtime protocol frame write loop rejects zero-byte syswrite' => sub {
  my $server = Overnet::Program::IRC::Server->new;
  my $error;

  {
    local *STDOUT;
    tie *STDOUT, 't::ZeroWriteHandle';
    $error = dies {
      $server->_send_message(
        {
          type   => 'notification',
          method => 'program.log',
          params => {
            level   => 'info',
            message => 'test',
          },
        }
      );
    };
  }

  like $error, qr/failed\ to\ write\ runtime\ protocol\ frame/mx, 'zero-byte runtime write is fatal';
};

done_testing;

{

  package t::ZeroWriteHandle;

  sub TIEHANDLE {
    my ($class) = @_;
    return bless {calls => 0}, $class;
  }

  sub WRITE {
    my ($self) = @_;
    $self->{calls} += 1;
    return 0 if $self->{calls} == 1;
    die "write loop continued after zero-byte write\n";
  }
}
