#!/usr/bin/perl
# 
# *Nix Security Scanner v1.0: nss.pl
# For use on Unix and Linux hosts
  
# See function sub HELP_MESSAGE() definition for command line options
# Location of configuration file is /etc/nss.<OS>.conf
   
# 20081130 donj Initial
# 20081208 donj Added port map and password file check
# 20081227 donj Added configuration file, email and paging
# 20081229 donj Handled configuration file entry with no value, added utility paths, 24 hr activity
# 20090105 donj Modifications for Solaris
# 20090106 donj Created firewall subs and used Perl regexps instead of egrep for Linux firewall analysis
# 20090107 donj Added check for "tcp_map" equals "yes" before creating baseline port map
# 20090108 donj Add uptime to report header, other format changes, no email option, fix for empty host variable, ignore log records older than old year old
# 20090119 donj Add help facility
# 20090121 donj Bug fix: misplaced exit statement
# 20090204 donj Changed upper bound on X11 ports from 6020 to 6029
# 20090318 donj Add the ability to ignore a band of udp and/or tcp ports when baselining
# 20090319 donj Baseline all ports and only ignore when comparing
# 20090713 donj Added to code to handle different compressed log file extensions
# 20090722 donj Improved code to handle different compressed log file extensions
# 20090722 donj Fixed bug where program did not detect firewall not running and also stopped firewall check
# from doing DNS lookups 
# 20100310 donj Allowed Cmnd_Alias line in /etc/sudoers, improved filtering for nmap output, and checked for rsyslog.conf instead of syslog.conf
# 20100815 donj Check that service "iptables" is turned on instead of "firewall" for users who are using default Redhat's default iptables service instead of custom firewall service
# 20110101 donj Allow firewall checking for either "firewall" or "iptables" services
# 20110103 donj Add runlevel configuration path variable
# 20110627 donj Add ability to ignore some tcp wrapper daemons    
# 20120608 donj Add "-y" switch to yum command that installs "nmap"

use strict;
use warnings;
use File::Copy;
use Getopt::Std;
use Cwd;
use Time::Local;

$main::VERSION = "1.0";
$Getopt::Std::STANDARD_HELP_VERSION = "true";
sub HELP_MESSAGE();

if ( !-d "/var/tmp/nss" ) {
    mkdir("/var/tmp/nss");
    chmod( 0700, '/var/tmp/nss' );
}
if ( !-d "/var/log/nss" ) {
    mkdir("/var/log/nss");
    chmod( 0700, '/var/log/nss' );
}

my %options = ();
getopts( "bpwvn", \%options );
my @log;
my $test;
my $line;
my @lines;
my @proclines;
my $file;
my $port;

sub line_processor;
sub trim_array;
sub parse_field;
sub get_date;
sub get_time;
sub extract_epoch_time;
sub month_to_num;
sub check_firewall_running_redhat;
sub check_firewall_running_solaris;
sub delete_old_records;
my ( $date, $formatted_date, $yesterday ) = get_date();
my $time = get_time();
my @filelist;
my @filelist2;
my @portlist;
my @diffout;
my @userlist;
my $cmdout;
my @nmapout;
my @nmapouttmp;
my %config;
my @fields;
my $offset;
my $length;
my $minlen;
my $epochtime;
my $onedaysecs = 86400;
my $datadir;
my $minchgs;
my $user;
my %users;
my $islastyear;
my $linux_dist = "unknow";

# Read in configuration file
my @pager_addresses;
my @mail_addresses;
my @sudoer_users;
my @fields_space;
my @fields_comma;
my $config_file;
if ( -e "/etc/nss.redhat.conf" ) {
    $config_file = "/etc/nss.redhat.conf";
}
elsif ( -e "/etc/nss.ubuntu.conf" ) {
    $config_file = "/etc/nss.ubuntu.conf";
}
elsif ( -e "/etc/nss.solaris.conf" ) {
    $config_file = "/etc/nss.solaris.conf";
}
else {
    print("Can't find configuration file: /etc/nss.<OS>.conf\n");
    exit(2);
}

# Set configuration defaults
$config{'mail_addresses'} = "";
$config{'sudoer_check'} = "no";
$config{'sudoer_users'} = "";
$config{'sshd_check'} = "no";
$config{'udp_map'} = "no";
$config{'udp_min_changes'} = 0;
$config{'tcp_map'} = "no";
$config{'tcp_min_changes'} = 0;
$config{'x11_port_ignore_lower'} = 65536;
$config{'x11_port_ignore_upper'} = -1;
$config{'udp_port_ignore_lower'} = 65536;
$config{'udp_port_ignore_upper'} = -1;
$config{'tcp_port_ignore_lower'} = 65536;
$config{'tcp_port_ignore_upper'} = -1;
$config{'passwd_check'} = "no";
$config{'tcp_wrappers_check'} = "no";
$config{'tcp_wrappers_ignore_daemons'} = "lockd rquotad mountd statd";
$config{'firewall_check'} = "no ";
$config{'selinux_check'} = "no";
$config{'todays_activity'} = "no";
$config{'log_write'} = "no";
$config{'uname_path'} = "/bin/uname";
$config{'nmap_path'} = "/usr/bin/nmap";
$config{'diff_path'} = "/usr/bin/diff";
$config{'cat_path'} = "/bin/cat";
$config{'mailx_path'} = "/bin/mailx";
$config{'last_path'} = "/usr/bin/last";
$config{'yum_path'} = "/usr/bin/yum";
$config{'iptables_path'} = "/sbin/iptables";
$config{'chkconfig_path'} = "/sbin/chkconfig";
$config{'getenforce_path'} = "/usr/sbin/getenforce";
$config{'uptime_path'} = "/usr/bin/uptime";
$config{'hostname_path'} = "/bin/hostname";
$config{'runlevel_path'} = "/sbin/runlevel";

if ( line_processor( \@proclines, $config_file ) == 0 ) {
    foreach (@proclines) {
        @fields = split( ' ', $_, 2 );
        chomp(@fields);
        trim_array( \@fields );
        if ( $fields[0] eq "pager_addresses" ) {
            parse_field( \%config, \@fields, \@pager_addresses );
        }
        elsif ( $fields[0] eq "mail_addresses" ) {
            parse_field( \%config, \@fields, \@mail_addresses );
        }
        elsif ( $fields[0] eq "sudoer_users" ) {
            parse_field( \%config, \@fields, \@sudoer_users );
        }
        else {
            $config{ $fields[0] } = $fields[1];
        }
    }

    ## Determine name of operating system
    $cmdout = `$config{'uname_path'} -s`;
    chomp($cmdout);
    $config{"os"} = lc($cmdout);
    if ( $config{'os'} ne "sunos" && $config{'os'} ne "linux" ) {
        print "Unknown operating system: %s\n" . $config{'os'};
        exit(1);
    }

    ## Determine Linux flavor 
    if ( $config{'os'} eq "linux" ) {
		if ( -e "/etc/redhat-release" ){
			$linux_dist = "redhat";
		}
		else {
    		$cmdout = `$config{'uname_path'} -v | grep -o Ubuntu`;
    		chomp($cmdout);
    		$cmdout = lc($cmdout);
			if ( $cmdout eq "ubuntu" ){
				$linux_dist = "ubuntu";
			}
			else {
				print "Unknown Linux distribution\n";
				exit(1);
			}
		}
	}

    if ( $config{'os'} ne "sunos" && $config{'os'} ne "linux" ) {
        print "Unknown operating system: %s\n" . $config{'os'};
        exit(1);
    }

    ## Determine name of host
    $cmdout = lc( `hostname` );
    chomp($cmdout);
    if ( $cmdout eq "" ) {
        $cmdout = `$config{'hostname_path'}`;
        chomp($cmdout);
    }
    @fields = split( '\.', $cmdout );
    $config{"hostname"} = $fields[0];

    if ( defined $options{'p'} ) {
        foreach (@proclines) {
            @fields = split( ' ', $_, 2 );
            if ( $fields[0] =~ /addresses|users/ ) {
                print "$fields[0]  ";
                for (
                    my $i = 0 ;
                    $i < scalar( @{ $config{ $fields[0] } } ) ;
                    $i++
                  )
                {
                    print "$config{$fields[0]}[$i] ";
                }
                print "\n";
            }
            else {
                print "$fields[0]  $config{$fields[0]}\n";
            }
        }
        print "os  $config{'os'}\n";
        print "hostname  $config{'hostname'}\n";
        exit(0);
    }
}
else {
    print "Unable to read configuration file nss.<OS>.conf";
    exit(2);
}

# Create new baseline files
if ( defined $options{'b'} ) {
    print "Creating new baseline files...\n";
    ## Save a copy of the password file
    copy( "/etc/passwd", "/var/tmp/nss/passwd.$date" )
      or die \"/etc/passwd cannot be copied";

    ## Save the open port configuration
    if (   $config{'tcp_map'} eq "yes"
        && !-e $config{'nmap_path'} )
    {
        print
"Nmap is not installed; please install before using NSS or change the 'tcp_map' \
	option in the nss.conf file to 'no'.\n";
        exit(1);
    }
    if ( $config{'udp_map'} && $config{'udp_map'} =~ /yes/i ) {
        @nmapouttmp = `$config{'nmap_path'} -p0-32767 -P0 -sU -r localhost`;
		foreach (@nmapouttmp) {
		  if($_ =~ /^\d.+\/udp\s+open\S*\s+\S+$/) {
		    push(@nmapout,$_);	
		  }
		}
		undef(@nmapouttmp);
        open( FILE, ">/var/tmp/nss/nmap.udp.$date" );
        print( FILE @nmapout );
        close(FILE);
    }

    if ( $config{'tcp_map'} && $config{'tcp_map'} =~ /yes/i ) {
        if ( $config{'os'} eq 'sunos' ) {
            $datadir = $config{'nmap_datadir'};
            @nmapouttmp =
              `$config{'nmap_path'} --datadir $datadir -P0 -sT -r localhost`;
        }
        else {
            @nmapouttmp = `$config{'nmap_path'} -p0-65535 -P0 -sT -r localhost`;
        }
		foreach (@nmapouttmp) {
		  if($_ =~ /^\d.+\/tcp\s+open\S*\s+\S+$/) {
		    push(@nmapout,$_);	
		  }
		}
		undef(@nmapouttmp);
        open( FILE, ">/var/tmp/nss/nmap.tcp.$date" );
		print (FILE @nmapout);
        close(FILE);
    }
    print "New baseline files created in /var/tmp/nss\n";
    exit(0);
}

# Write log header
push( @log,
        "NSS Security Report for "
      . uc( $config{'hostname'} )
      . " on $formatted_date at $time\n" );
$cmdout  = `$config{'uptime_path'}`;
my @halves = split(/average: /,$cmdout);
my @uptime  = split( ' ', $halves[0] );
my $hmlabel;
my $comma_count;
$comma_count++ while $halves[0] =~ /,/g;
my $uptime1;
if($comma_count == 2) {
  if($uptime[2] =~ ':') {
	$hmlabel = "hour(s)";
  }
  else {
	$hmlabel = "minute(s)";
  }
  $uptime1 = "Up for $uptime[2] $hmlabel ";
}
elsif($comma_count == 3) {
  if($uptime[4] =~ ':') {
	$hmlabel = "hour(s)";
  }
  else {
	$hmlabel = "minute(s)";
  }
  $uptime1 = "Up for $uptime[2] day(s) $uptime[4] $hmlabel ";
}
$uptime1 =~ tr/,//d;
my $uptime2 = "with 1, 5, & 15 minute load averages of ";
push( @log, $uptime1 . $uptime2 . $halves[1] );

# Add last 24 hours login, sudo and reboot activity to the log
if ( $config{'todays_activity'} && $config{'todays_activity'} =~ /yes/i ) {
    if ( defined $options{'v'} ) {
        print("Checking activity in the last 24 hours...\n");
    }
    push( @log, "\n*** Activity in the Last 24 Hours ***" );
    $epochtime = time();

    ## Look for sudoers
    if ( defined $options{'v'} ) {
        print("\tLooking for sudoers...\n");
    }
    my $log1 = "";
    my $log2 = "";
    my $log3 = "";
    if ( $config{'os'} eq "linux" ) {
        $log1 = "/var/log/secure";
        $log2 = "/var/log/secure.1";
    }
    elsif ( $config{'os'} eq "sunos" ) {
        $log1 = "/var/log/local2";
        $log2 = "/var/log/oldlogs/local2.$date";
        $log3 = "/var/log/oldlogs/local2.$yesterday";
        my $temp = $log2 . ".gz";
        if ( -e $temp ) {
            $cmdout = `$config{'gunzip_path'} $temp`;
        }
        $temp = $log3 . ".gz";
        if ( -e $temp ) {
            $cmdout = `$config{'gunzip_path'} $temp`;
        }
    }
    else {
        print "Unknown operating system: %s\n" . $config{'os'};
        exit(1);
    }

    my @sudo       = ();
    my @sudo_found = ();
    if ( -e $log1 ) {
        open( FILE, "<$log1" );
        if ( defined $options{'v'} ) {
            print("\tReading in first log file...\n");
        }
        @sudo = <FILE>;
        close(FILE);
        if ( defined $options{'v'} ) {
            print("\tScanning first log file...\n");
        }
        foreach (@sudo) {
            if ( $_ =~ /sudo:/ ) {
                push( @sudo_found, $_ );
            }

        }
    }
    if ( -e $log2 ) {
        open( FILE, "<$log2" );
        if ( defined $options{'v'} ) {
            print("\tReading in second log file...\n");
        }
        @sudo = <FILE>;
        close(FILE);
        if ( defined $options{'v'} ) {
            print("\tScanning second log file...\n");
        }
        foreach (@sudo) {
            if ( $_ =~ /sudo:/ ) {
                push( @sudo_found, $_ );
            }

        }
    }
    if ( defined($log3) && -e $log3 ) {
        open( FILE, "<$log3" );
        if ( defined $options{'v'} ) {
            print("\tReading in third log file...\n");
        }
        @sudo = <FILE>;
        close(FILE);
        if ( defined $options{'v'} ) {
            print("\tScanning third log file...\n");
        }
        foreach (@sudo) {
            if ( $_ =~ /sudo:/ ) {
                push( @sudo_found, $_ );
            }

        }
        @sudo = ();
    }

    $offset = 0;
    $length = 12;
    delete_old_records( \@sudo_found, $offset, $length );
    $minlen = $offset + $length;
    %users  = ();
    my $user_offset = $config{'os'} eq "linux" ? 5 : 8;
    foreach (@sudo_found) {
        if ( length($_) >= $minlen ) {
            if (
                (
                    $epochtime -
                    extract_epoch_time( $_, $offset, $length, \$islastyear )
                ) < $onedaysecs
              )
            {
                chomp($_);
                $users{ ( split( ' ', $_ ) )[$user_offset] } = "";
            }
        }
    }
    @sudo_found = ();
    if ( scalar( keys(%users) ) > 0 ) {
        $line = "sudo by: ";
        foreach ( keys %users ) {
            $line = $line . $_ . " ";
        }
        $line = $line . "\n";
        push( @log, $line );
    }
    else {
        push( @log, "sudo by: none\n" );
    }

    ## Look for logins
    if ( defined $options{'v'} ) {
        print("\tLooking for logins and reboots...\n");
    }
    my @logins  = `$config{'last_path'}`;
    my %users   = ();
    my @reboots = ();
    $offset = 43;
    $length = 12;
    delete_old_records( \@logins, $offset, $length );
    $minlen = $offset + $length;

    foreach (@logins) {
        if ( length($_) >= $minlen ) {
            if (
                (
                    $epochtime -
                    extract_epoch_time( $_, $offset, $length, \$islastyear )
                ) < $onedaysecs
              )
            {
                if ( $_ =~ /^reboot/i ) {
                    push( @reboots, substr( $_, $offset, $length ) );
                }
                else {
                    $users{ ( split( ' ', $_ ) )[0] } = "";
                }
            }
        }
    }
    if ( scalar( keys(%users) ) > 0 ) {
        $line = "logins by: ";
        foreach ( keys %users ) {
            $line = $line . $_ . " ";
        }
        $line = $line . "\n";
        push( @log, $line );
    }
    else {
        push( @log, "logins by: none\n" );
    }

    ## Look for reboots
    if ( scalar(@reboots) > 0 ) {
        $line = "reboots at time(s): ";
        foreach (@reboots) {
            $line = $line . $_ . " ";
        }
        $line = $line . "\n";
        push( @log, $line );
    }
    else {
        push( @log, "reboots at time(s): none\n" );
    }
    @logins = ();
}

# Look for new users
if ( $config{'passwd_check'} && $config{'passwd_check'} =~ /yes/i ) {
    if ( defined $options{'v'} ) {
        print("Looking for new users...\n");
    }
    opendir( DIR, "/var/tmp/nss" );
    @filelist = readdir(DIR);
    closedir(DIR);
    @filelist2 = ();
    foreach (@filelist) {
        if ( $_ =~ 'passwd' ) {
            push( @filelist2, $_ );
        }
    }
    undef(@filelist);
    @filelist2 = sort(@filelist2);
    $file      = pop(@filelist2);
    undef(@filelist2);
    $file = "/var/tmp/nss/" . $file;
    ## Compare current password file against baseline file
    @diffout  = ();
    @diffout  = `$config{'diff_path'} /etc/passwd $file`;
    @userlist = ();
    foreach (@diffout) {
        if ( $_ =~ '^< ' ) {
            push( @userlist, $_ );
        }
    }
    undef(@diffout);
    if ( scalar(@userlist) != 0 ) {
        push( @log, "Warning: New users found:\n" );
        push( @log, @userlist );
    }
    else {
        push( @log, "No new users found\n" );
    }
    undef(@userlist);
}

# Test for change in UDP port configuration
if ( $config{'udp_map'} && $config{'udp_map'} =~ /yes/i ) {
    if ( defined $options{'v'} ) {
        print("Looking for changes in UDP port configuration...\n");
    }
    $test = 0;
    unlink("/var/tmp/nss/nmap.udp.temp");
    opendir( DIR, "/var/tmp/nss" );
    @filelist = readdir(DIR);
    closedir(DIR);
    @filelist2 = ();
    foreach (@filelist) {

        if ( $_ =~ 'nmap.udp' ) {
            push( @filelist2, $_ );
        }
    }
    undef(@filelist);
    @filelist2 = sort(@filelist2);
    $file      = pop(@filelist2);
    undef(@filelist2);
    $file = "/var/tmp/nss/" . $file;

    ## Create current port map
    @nmapouttmp = `$config{'nmap_path'} -p0-32767 -sU -r localhost`;
	foreach (@nmapouttmp) {
	  if($_ =~ /^\d.+\/udp\s+open\S*\s+\S+$/) {
		push(@nmapout,$_);	
	  }
	}
	undef(@nmapouttmp);
    open( FILE, ">/var/tmp/nss/nmap.udp.temp" );
    foreach (@nmapout) {
        $port = ( split( '/', $_ ) )[0];
        if (  
			!(
				$port >= $config{'udp_port_ignore_lower'} 
				&& $port <= $config{'udp_port_ignore_upper'}
			 )
          )
        {
            print FILE "$_";
        }
    }
    undef(@nmapout);
    close(FILE);

    ## Compare current port map against baseline map
    @diffout  = ();
    @diffout  = `$config{'diff_path'} /var/tmp/nss/nmap.udp.temp $file`;
    @portlist = ();
    foreach (@diffout) {
        if ( $_ =~ '^< ' ) {
            push( @portlist, $_ );
        }
    }
    undef(@diffout);
    $minchgs = 1;
    if ( $config{'udp_min_changes'} ) {
        $minchgs = $config{'udp_min_changes'};
    }
    if ( scalar(@portlist) >= $minchgs ) {
        $test++;
        push( @log, "Warning: New UDP port(s) found:\n" );
        push( @log, @portlist );
    }
    undef(@portlist);
    if ( $test == 0 ) {
        push( @log, "No new UDP ports found\n" );
    }
}

# Test for change in TCP port configuration
if ( $config{'tcp_map'} && $config{'tcp_map'} =~ /yes/i ) {
    if ( defined $options{'v'} ) {
        print("Looking for changes in TCP port configuration...\n");
    }
    $test = 0;
    unlink("/var/tmp/nss/nmap.tcp.temp");
    opendir( DIR, "/var/tmp/nss" );
    @filelist = readdir(DIR);
    closedir(DIR);
    @filelist2 = ();
    foreach (@filelist) {

        if ( $_ =~ 'nmap.tcp' ) {
            push( @filelist2, $_ );
        }
    }
    undef(@filelist);
    @filelist2 = sort(@filelist2);
    $file      = pop(@filelist2);
    undef(@filelist2);
    $file = "/var/tmp/nss/" . $file;

    ## Create current port map
    if ( $config{'os'} eq 'sunos' ) {
        $datadir = $config{'nmap_datadir'};
        @nmapouttmp =
          `$config{'nmap_path'} --datadir $datadir -P0 -sT -r localhost`;
    }
    else {
        @nmapouttmp = `$config{'nmap_path'} -p0-65535 -P0 -sT -r localhost`;
    }
	foreach (@nmapouttmp) {
	  if($_ =~ /^\d.+\/tcp\s+open\S*\s+\S+$/) {
		push(@nmapout,$_);	
	  }
	}
	undef(@nmapouttmp);
    open( FILE, ">/var/tmp/nss/nmap.tcp.temp" );
    foreach (@nmapout) {
        $port = ( split( '/', $_ ) )[0];
        if (  
            !(
                $port >= $config{'x11_port_ignore_lower'}
                && $port <= $config{'x11_port_ignore_upper'}
            )
			&&
			!(
				$port >= $config{'tcp_port_ignore_lower'} 
				&& $port <= $config{'tcp_port_ignore_upper'}
			 )
          )
        {
            print FILE "$_";
        }
    }
    undef(@nmapout);
    close(FILE);

    ## Compare current port map against baseline map
    @diffout  = ();
    @diffout  = `$config{'diff_path'} /var/tmp/nss/nmap.tcp.temp $file`;
    @portlist = ();
    foreach (@diffout) {
        if ( $_ =~ '^< ' ) {
            push( @portlist, $_ );
        }
    }
    undef(@diffout);
    $minchgs = 1;
    if ( $config{'tcp_min_changes'} ) {
        $minchgs = $config{'tcp_min_changes'};
    }
    if ( scalar(@portlist) >= $minchgs ) {
        $test++;
        push( @log, "Warning: New TCP port(s) found:\n" );
        push( @log, @portlist );
    }
    undef(@portlist);
    if ( $test == 0 ) {
        push( @log, "No new TCP ports found\n" );
    }
}

# Begin system configuration section of report
push( @log, "\n*** System Configuration ***\n" );

# Check that SSHD is configured securely
if ( $config{'sshd_check'} && $config{'sshd_check'} =~ /yes/i ) {
    if ( defined $options{'v'} ) {
        print("Checking SSHD configuration...\n");
    }
    $test = 0;
    $file = "/etc/ssh/sshd_config";
    if ( line_processor( \@proclines, $file ) == 0 ) {
        foreach $line (@proclines) {
            if ( $line =~ 'PermitRootLogin' ) {
                if ( $line =~ '^PermitRootLogin\s*[Nn][Oo]' ) {
                    $test++;
                }
                if ( $line !~ 'PermitRootLogin\s*[Nn][Oo]' ) {
                    $test--;
                    push( @log,
                        "WARNING: File $file is insecurely configured: $line" );
                }
            }
            if ( $line =~ 'PermitEmptyPasswords\s*[Yy][Ee][Ss]' ) {
                $test--;
                push( @log,
                    "WARNING: File $file is insecurely configured: $line" );
            }
        }
        if ( $test == 1 ) {
            push( @log, "OK: SSHD is configured securely\n" );
		}
		else {
            push( @log, "WARNING: SSH may not be configured securely\n" );
        }
    }
}

# Check that TCP wrappers is properly configured
if ( $config{'tcp_wrappers_check'} && $config{'tcp_wrappers_check'} =~ /yes/i )
{
    if ( defined $options{'v'} ) {
        print("Checking TCP wrappers configuration...\n");
    }
    $test = 0;
    $file = "/etc/hosts.deny";
    if ( line_processor( \@proclines, $file ) == 0 ) {
        foreach $line (@proclines) {
            if ( $line =~ '^ALL\s*:\s*ALL' ||
					$line =~ '^ALL\s*:\s*PARANOID'  ) {
                $test++;
            }
        }
        if ( $test == 0 ) {
            push( @log, "WARNING: TCP wrapper file $file is insecurely configured: $line" );
        }
    }

	my @ignore_daemons = split(' ',$config{'tcp_wrappers_ignore_daemons'});
	my $daemon;
	my $skip=0;
    $file = "/etc/hosts.allow";
    if ( line_processor( \@proclines, $file ) == 0 ) {
        foreach $line (@proclines) {
		  foreach $daemon (@ignore_daemons) {
			if( $line =~ /$daemon/) {
				$skip = 1;
			}
		  }
          if ( !$skip && $line =~ '.*:\s*ALL' ) {
			$test--;
            if ( $line !~ /\n^/ ) {
              $line = $line . "\n";
            }
            push( @log, "WARNING: TCP wrapper file $file is insecurely configured: $line" );
		  }
		  $skip=0;
        }
        if ( $test >= 1 ) {
            push( @log, "OK: TCP wrappers is enabled\n" );
        }
    }
}

# Check that sudoers is configured securely
if ( $config{'sudoer_check'} && $config{'sudoer_check'} =~ /yes/i ) {
    if ( defined $options{'v'} ) {
        print("Checking sudoers configuration...\n");
    }
    my $nousers = scalar( @{ $config{'sudoer_users'} } );
    if ( $config{'sudoer_users'} && $nousers > 0 ) {
        my $cmpstr = "^Cmnd_Alias\\s*|^Defaults\\s*|^root\\s*";
        foreach $user ( @{ $config{'sudoer_users'} } ) {
            $cmpstr = $cmpstr . "|^" . $user . "\\s*";
        }
        $test = 0;
        $file = "/etc/sudoers";
        if ( line_processor( \@proclines, $file ) == 0 ) {
            foreach $line (@proclines) {
                if ( $line !~ $cmpstr ) {
                    $test--;
                    push( @log,
                        "WARNING: File $file is insecurely configured: $line" );
                }
            }
            if ( $test == 0 ) {
                push( @log, "OK: Sudoers is configured securely\n" );
            }
        }
    }
    else {
        push( @log,
            "WARNING: Permitted sudo users not specified in configuration file"
        );
    }
}

# Check for active firewall with input chains and drop rules
if ( $config{'firewall_check'} && $config{'firewall_check'} =~ /yes/i ) {
    if ( defined $options{'v'} ) {
        print("Checking firewall...\n");
    }
    if ( $config{'os'} eq "linux" && $linux_dist eq "redhat" ) {
        $test = check_firewall_running_redhat() eq "yes" ? 1 : 0;
        $cmdout = `$config{'chkconfig_path'} --list "iptables"`;
        if ( $cmdout =~ '3\:on' ) {
            $test++;
        }
        if ( $cmdout =~ '5\:on' ) {
            $test++;
        }
		if ( $test == 3 ) {
            push( @log, "OK: Firewall is enabled and running\n" );
        }
        else {
            push( @log, "WARNING: There is a problem with the firewall\n" );
        }
    }
    elsif ( $config{'os'} eq "linux" && $linux_dist eq "ubuntu" ) {
		my @cmdout = `ufw status`;
		chomp($cmdout[0]);
        if ( $cmdout[0] eq "Status: active" ) {
            push( @log, "OK: Firewall is enabled and running\n" );
        }
        else {
            push( @log, "WARNING: There is a problem with the firewall\n\n" );
        }
	}
    elsif ( $config{'os'} eq "sunos" ) {
        $test = check_firewall_running_solaris() eq "yes" ? 1 : 0;
        if ( -r "/etc/ipf/ipf.conf" ) {
            $test++;
        }
        if ( -x "/usr/local/bin/ipfilter" ) {
            $test++;
        }
        if ( $test == 3 ) {
            push( @log, "OK: Firewall is enabled and running\n" );
        }
        else {
            push( @log, "WARNING: There is a problem with the firewall\n\n" );
        }
    }
    else {
        printf("Unknown operating system: %s\n", $config{'os'});
        exit(1);
    }
}

# Check that Selinux is properly configured
if ( $config{'selinux_check'} && $config{'selinux_check'} =~ /yes/i ) {
    if ( defined $options{'v'} ) {
        print("Checking Selinux configuration...\n");
    }
    $test = 0;
    $file = "/etc/sysconfig/selinux";
    if ( line_processor( \@proclines, $file ) == 0 ) {
        foreach $line (@proclines) {
            if ( $line =~ '^SELINUX\s*=' ) {
                if ( $line =~ '^SELINUX\s*=\s*enforcing' ) {
                    $test++;
                }
                else {
                    push( @log,
                        "WARNING: File $file is not configured: $line" );
                }
            }
        }
        $cmdout = `$config{'getenforce_path'}`;
        chomp($cmdout);
        if ( $cmdout eq "Enforcing" ) {
            $test++;
        }
        else {
            push( @log, "WARNING: Selinux is off\n" );
        }
        if ( $test == 2 ) {
            push( @log, "OK: Selinux is enabled and running\n" );
        }
    }
}

# Create warning string
my $warningstr = "";
my $firsttime  = "yes";
foreach (@log) {
    if ( $_ =~ /^WARNING/i ) {
        chomp($_);
        if ( $firsttime eq "yes" ) {
            $firsttime  = "no";
            $warningstr = " - " . $_;
        }
        else {
            $warningstr = $warningstr . " - " . $_;
        }
    }
}

# Write out results to a log
if ( $config{'log_write'} && $config{'log_write'} =~ /yes/i ) {
    if ( defined $options{'v'} ) {
        print("Writing results to log...\n");
    }
    open( FILE, ">/var/log/nss/nss.$date.log" );
    foreach (@log) {
        if ( $_ =~ /\n$/ ) {
            print( FILE "$_" );
        }
        else {
            print( FILE "$_\n" );
        }
    }
    close(FILE);
}

# Email and paging
if ( !defined $options{'n'} ) {
    $cmdout = `ls $config{'mailx_path'}`;
    my $logstr;
    if ( $cmdout !~ /No such file/ ) {
        if ( defined $options{'v'} ) {
            print("Sending emails and paging...\n");
        }
        ## Send email
        my $uc_hostname = uc( $config{'hostname'} );
        if ( $config{'mail_addresses'}
            && scalar( @{ $config{'mail_addresses'} } ) > 0 )
        {
            if ( !defined $options{'w'} || $warningstr ) {
                if ( $warningstr eq "" ) {
                    $logstr = "\nMailed report to: ";
                }
                else {
                    $logstr = "\nMailed alert to: ";
                }
                foreach $user ( @{ $config{'mail_addresses'} } ) {
                    if ( $warningstr eq "" ) {
`$config{'cat_path'} /var/log/nss/nss.$date.log | $config{'mailx_path'} -s "Security Report for $uc_hostname" $user`;
                    }
                    else {
`$config{'cat_path'} /var/log/nss/nss.$date.log | $config{'mailx_path'} -s "SECURITY ALERT for $uc_hostname" $user`;
                    }
                    $logstr = $logstr . $user . " ";
                }
                $logstr = $logstr . "\n";
            	push( @log, $logstr );
            }
        }

        ## Page systems administrators
        if (   $warningstr
            && $config{'pager_addresses'}
            && scalar( @{ $config{'pager_addresses'} } ) > 0 )
        {
            $logstr = "Alerting : ";
            foreach $user ( @{ $config{'pager_addresses'} } ) {
`$config{'cat_path'} /var/log/nss/nss.$date.log | $config{'mailx_path'} -s "SECURITY ALERT for $uc_hostname $warningstr" $user`;
                $logstr = $logstr . $user . " ";
            }
            $logstr = $logstr . "\n";
            push( @log, $logstr );
        }
    }
    else {
        print("WARNING: Mailer program 'mailx' is missing!\n");
    }
}

# Print out final report when in verbose mode
if ( defined $options{'v'} ) {
    print("\n");
    foreach (@log) {
        if ( $_ =~ /\n$/ ) {
            print("$_");
        }
        else {
            print("$_\n");
        }
    }
}
exit(0);

sub line_processor {
    my ( $pProclines, $file ) = @_;
    undef(@$pProclines);
    my $line;
    my @lines;
    my $lastline = "";
    my $cont     = "no";
    if ( -r $file ) {
        open( INFILE, "<$file" );
        @lines = <INFILE>;
        foreach $line (@lines) {
            if ( !( $line =~ '^#' || $line =~ '^$' ) ) {

                # Handle line continuation case
                ## beginning
                if ( $line =~ '\\\s*$' && $cont eq "no" ) {
                    $cont = "yes";
                    chomp($line);
                    $line =~ s/\\//;
                    $line =~ s/ +/ /;
                    $lastline = $line;
                }
                ## middle
                elsif ( $line =~ '\\\s*$' && $cont eq "yes" ) {
                    chomp($line);
                    $line =~ s/\\//;
                    $line =~ s/ +/ /;
                    $lastline = $lastline . $line;
                }
                ## end
                elsif ( $line !~ '\\\s*$' && $cont eq "yes" ) {
                    $cont = "no";
                    chomp($line);
                    $line =~ s/ +/ /;
                    $line = $line . "\n";
                    $line = $lastline . $line;
                }
                if ( $cont eq "no" ) {
                    push( @$pProclines, $line );
                }
            }
        }
        close(INFILE);
        return 0;
    }
    else {
        return 1;
    }
}

sub trim_array {
    my ($pArray) = @_;
    for ( my $i = 0 ; $i < scalar(@$pArray) ; $i++ ) {
        $$pArray[$i] =~ s/^\s+//;
        $$pArray[$i] =~ s/\s+$//;
    }
}

sub parse_field {
    my @fields_space;
    my @fields_comma;
    my ( $pConfig, $pFields, $pUserOrAddrList ) = @_;
    $$pConfig{ $$pFields[0] } = $pUserOrAddrList;
    if ( $$pFields[1] eq "" ) {
        return (0);
    }
    @fields_space = split( ' ', $$pFields[1] );
    @fields_comma = split( ',', $$pFields[1] );
    trim_array( \@fields_space );
    trim_array( \@fields_comma );
    if ( scalar(@fields_space) > scalar(@fields_comma) ) {
        $$pConfig{ $$pFields[0] } = ();
        for ( my $i = 0 ; $i < scalar(@fields_space) ; $i++ ) {
            $$pConfig{ $$pFields[0] }[$i] = $fields_space[$i];
        }
    }
    else {
        $$pConfig{ $$pFields[0] } = ();
        for ( my $i = 0 ; $i < scalar(@fields_comma) ; $i++ ) {
            $$pConfig{ $$pFields[0] }[$i] = $fields_comma[$i];
        }
    }
}

sub get_date {
    my $onedaysecs         = 86400;
    my $epochtime          = time();
    my $epochtimeyesterday = $epochtime - $onedaysecs;
    my @f = ( localtime($epochtime) )[ 3 .. 5 ];   # grabs day/month/year values
    $f[1]++;
    $f[2] += 1900;
    my $day   = sprintf( "%02d", $f[0] );
    my $month = sprintf( "%02d", $f[1] );
    my $date           = "$f[2]" . "$month" . "$day";
    my $formatted_date = "$month/" . "$day/" . "$f[2]";
    @f =
      ( localtime($epochtimeyesterday) )[ 3 .. 5 ]
      ;                                            # grabs day/month/year values
    $f[1]++;
    $f[2] += 1900;
    $day   = sprintf( "%02d", $f[0] );
    $month = sprintf( "%02d", $f[1] );
    $yesterday = "$f[2]" . "$month" . "$day";
    return ( $date, $formatted_date, $yesterday );
}

sub get_time {
    my @f = (localtime)[ 0 .. 2 ];                 # grabs sec/min/hour values
    foreach (@f) {
        $_ = sprintf( "%02d", $_ );
    }
    return "$f[2]:$f[1]:$f[0]";
}

sub extract_epoch_time {
    my ( $str, $offset, $length, $pIslastyear ) = @_;
    my $logmonth;
    my $logyear;
    my @logdatetime;
    my @logtime;
    my $epochtime;
    chomp($str);
    @logdatetime = split( ' ', substr( $str, $offset, $length ) );
    @logtime = split( ':', $logdatetime[2] );
    $logmonth  = month_to_num( $logdatetime[0] );
    $logyear   = (localtime)[5];
    $epochtime = timelocal(
        "0",         "$logtime[1]", "$logtime[0]", "$logdatetime[1]",
        "$logmonth", "$logyear"
    );

# If extracted time is greater that local time, assume the log date is from last year
    if ( $epochtime > time() ) {
        $$pIslastyear = "yes";
        return ( $epochtime - 31536000 );
    }
    else {
        $$pIslastyear = "no";
        return ($epochtime);
    }
}

sub month_to_num {

    # Month returned is offset from January
    my $month = shift;
    if ( $month =~ /jan/i ) {
        return 0;
    }
    elsif ( $month =~ /feb/i ) {
        return 1;
    }
    elsif ( $month =~ /mar/i ) {
        return 2;
    }
    elsif ( $month =~ /apr/i ) {
        return 3;
    }
    elsif ( $month =~ /may/i ) {
        return 4;
    }
    elsif ( $month =~ /jun/i ) {
        return 5;
    }
    elsif ( $month =~ /jul/i ) {
        return 6;
    }
    elsif ( $month =~ /aug/i ) {
        return 7;
    }
    elsif ( $month =~ /sep/i ) {
        return 8;
    }
    elsif ( $month =~ /oct/i ) {
        return 9;
    }
    elsif ( $month =~ /nov/i ) {
        return 10;
    }
    elsif ( $month =~ /dec/i ) {
        return 11;
    }
    else {
        print "Invalid month string passed to function month_to_num: $month";
    }
}

sub check_firewall_running_redhat {
	if( $linux_dist eq "redhat") {
		my @lines         = `$config{'iptables_path'} -L -n`;
		my @input_chain   = ();
		my $input_ok      = "no";
		foreach (@lines) {
			if ( $_ !~ /^$/ && $_ !~ /^target/ ) {
				push( @input_chain, $_ );
			}
		}
		@lines = ();
		foreach (@input_chain) {
			if (   $_ =~ /Chain INPUT \(policy DROP\)/
				|| $_ =~ /^DROP\s+all\s+--\s+0.0.0.0\/0\s+0.0.0.0\/0\s*$/ )
			{
				$input_ok = "yes";
			}
		}
		if ( $input_ok eq "yes" ) {
			return ("yes");
		}
		else {
			return ("no");
		}
	}
	else {
		print "Ubuntu firewall\n";
	}
}

sub check_firewall_running_solaris {
    if ( !-e $config{'ipfstat_path'} ) {
        if ( defined $options{'p'} ) {
            print "Unable to find command $config{'ipfstat_path'}\n";
        }
        return ("no");
    }
    my @lines  = `$config{'ipfstat_path'} -io`;
    my $counti = 0;
    my $counto = 0;
    foreach (@lines) {
        if ( $_ =~ /block +in.+all/ ) {
            $counti++;

        }
        if ( $_ =~ /block +out.+all/ ) {
            $counto++;
        }
    }
    if ( $counti > 0 && $counto > 0 ) {
        return ("yes");
    }
    else {
        return ("no");
    }
}

sub delete_old_records {
    my ( $pLogins, $offset, $length ) = @_;
    my $minlen         = $offset + $length;
    my $islastyear     = "no";
    my $previous_state = $islastyear;
    my $currentndx     = 0;
    foreach ( @{$pLogins} ) {
        if ( length($_) >= $minlen ) {
            extract_epoch_time( $_, $offset, $length, \$islastyear );
            if ( $previous_state eq "yes" && $islastyear eq "no" ) {
                $currentndx = $currentndx > 0 ? $currentndx - 1 : 0;
                @{$pLogins} = @{$pLogins}[ 0 .. $currentndx ];
                last;
            }
        }
        $previous_state = $islastyear;
        $currentndx++;
    }
}

sub HELP_MESSAGE(){
print "\n";
print "Usage: nss.pl [OPTIONS]...\n";
print "       NSS - *Nix Security Scanner\n";
print "       Scan the system looking for security deficiencies or potential problems.\n";
print "\n";
print "       First scan logs for users that have logged in or sudoed in the last 24 hours\n";
print "       as well as if the system was rebooted.  Next, look for new network ports that have\n";
print "       opened up since the network baselines were created. Lastly, check that the system\n";
print "       is securely configured by examining: \n";
print "\n";
print "            -- secure shell is configured securely\n";      
print "            -- sudoers is configured securely\n";      
print "            -- firewall is configured and running\n";      
print "            -- for Linux hosts, selinux is configured and running\n";      
print "            -- log server is configured\n";      
print "            -- baseline is configured and running\n";      
print "\n";
print "Options:\n";
print "Arguments labeled as exclusive cannot be combined with any other options.\n";
print "\n";
print "       -b     create new baselines for users and network ports (exclusive).\n";
print "       -p     parse and print the configuration files (exclusive).\n";
print "       -w     only email or page systems administrators if there exist warnings.\n";
print "       -n     generate report, but do not email or page with results.\n";
print "       -v     verbose.\n";
print "\n";
print "Exit status is 0 if OK, 1 if minor problems, 2 if serious trouble.\n";
print "\n";
print "Report bugs to <donj\@bu.edu>.\n"
}
