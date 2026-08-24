use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

my $workflow_dir = File::Spec->catdir($FindBin::Bin, '..', '.github', 'workflows');
my @workflows    = qw(container.yml integration.yml mutation.yml test.yml);

for my $workflow (@workflows) {
  my $path = File::Spec->catfile($workflow_dir, $workflow);
  ok -f $path, "$workflow exists";

  open my $fh, '<', $path
    or die "unable to open $path: $!";
  local $/ = undef;
  my $content = <$fh>;

  like $content, qr{repository:\s+overnet-project/overnet-perl\b}mx,
    "$workflow checks out the Perl monorepo";
  like $content, qr{path:\s+irc-server\b}mx,
    "$workflow keeps the IRC checkout beside the monorepo distributions";
  unlike $content,
    qr{repository:\s+overnet-project/(?:core-perl|relay-perl|adapter-irc-perl|overnet-perl-style)\b}mx,
    "$workflow does not consume superseded component repositories";

  my $dependency_steps = () = $content =~ /name:\s+Install\s+dependencies/gmx;
  my $coherent_nostr_installs = () = $content =~ m{
    cpanm\s+--local-lib\s+~/perl5\s+--notest\s+--reinstall\s+
    Net::Nostr::Core\s+Net::Nostr::Client\s+Net::Nostr::Relay
  }gmx;
  is $coherent_nostr_installs, $dependency_steps,
    "$workflow refreshes the split Net::Nostr distributions in each dependency step";
}

done_testing;
