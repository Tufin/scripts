#!/usr/bin/perl
use lib '../extlib/lib/perl5';
use lib './extlib/lib/perl5';
use lib '/opt/tufin/securitysuite/ps/perl/extlib/lib/perl5';
use lib '../Tufin_Modules/lib';
use strict;
use warnings;
# Standard libs
use Getopt::Long;
use MIME::Base64;
use REST::Client;
use JSON;
use DBI;
require XML::LibXML;
use Config::Simple;

use Data::Dumper;
$Data::Dumper::Indent = 1;


###########################################################################################################
#
#This Perl Script is to select a set of rules to be analysed through APG.
#The purpose is to help the customer to provide a list of rules on a per firewall / policy basis
#
#
##########################################################################################################
#
# Author		: Stephane PEREZ
# Contact		: stephane.perez@tufin.com
#
##################################
#
# Revisions
#
# - Version 1.0    : Initial creation of the script
# - Version 1.1    : Added support to search rules by ID instead of Order for Fortinet
# - Version 1.2    : Added a cache mechanism for the rules to prevent multiple API calls.
# - Version 1.3    : Added support for Rule Number for Fortinet / Netscreen
#
#
#############################
#   TODO
#
# - Add capability to select duration and calculate the end-date
# - Add support for StoneSoft devices
# - Add support for Palo Alto devices
# - Add additional debugging and reporting.
#
##################################


use vars qw ($debug $help $testing $userid $device_name $policy_package $rules_list $acl_name $from_zone $to_zone $analysis_duration $rule_type);

my $prog_date    	= "4 November 2016";
my $prog_version        = "1.3";
my $start_run = time(); # We want to know how much time it took for the script to run (just for fun)

#Retrieving additional parameters.
print "INFO\nINFO  ----> Welcome to the APG multiple job creation script version $prog_version.\n",
    "INFO  ---->\n";

GetOptions(
	"debug=s"		=> \$debug,
        "help"        		=> \$help,
	"userid=s"		=> \$userid,
	"device-name=s"		=> \$device_name,
	"policy-package=s"	=> \$policy_package,
	"ACL=s"			=> \$acl_name,
	"from-zone=s"		=> \$from_zone,
	"to-zone=s"		=> \$to_zone,
	"rule-list=s"		=> \$rules_list,
        "rule-type=s"           => \$rule_type,
	"duration=s"		=> \$analysis_duration
        );

# Global vars

if (not defined ($debug)) {
	$debug = 0;
}

print "INFO\nINFO  ----> Welcome to the assign_validation_from_app script version $prog_version.\n",
    "INFO  ---->\n" if $debug eq 255;

if (defined ($help)) {
	print_usage();
	exit;
}
if (not defined ($analysis_duration)) {
	print "INFO  ----> Number of days of analysis not specified, assuming APG job duration of 6 months.\n";
	$analysis_duration = 183;
}

if (not defined ($policy_package)){
	$policy_package = "Standard";
}

if (not defined ($acl_name)){
	$acl_name = "";
}

if (not defined ($rule_type)){
    print "WARNING ----> Defaulting to rule order.\n";
    $rule_type = "order";
}
else{
        $rule_type = lc($rule_type);
        if($rule_type ne "id" and $rule_type ne "number" and $rule_type ne "order" and $rule_type ne "number"){
                print "ERROR ----> Invalid rule_type provided.\n";
                print_usage();
                exit;
        }
}

if ($rule_type eq "order") {
        if (not defined ($from_zone) or not defined ($to_zone)) {
                print "INFO  ----> Either Source or Destination zones is not defined, assuming global.\n";
                $from_zone = "";
                if (not defined ($to_zone)) {
                        $to_zone = "global";
                }
                if (not defined ($from_zone)) {
                        $from_zone = "global";
                }
        }
}


my @rules;
if (not defined ($rules_list)){
	print "ERROR ----> No rules specified.\n";
	print_usage();
	exit;
}
else{
	my @l_temp_rules = split (',', $rules_list);
	print "DEBUG ----> We have a list of rules, calculating the final list to collect.\n" if ($debug ne 0);
	while (@l_temp_rules) {
		my $l_value = shift @l_temp_rules;
		if ($l_value =~ m/.*-.*/){
			my $l_low_value = $l_value;
			my $l_high_value = $l_value;
			$l_low_value =~ s/(\d+)-*.*/$1/;
			$l_high_value =~ s/.*-(\d+)/$1/;
			for (my $i = $l_low_value ; $i <= $l_high_value ; $i++){
				push @rules,$i;
				print "DEBUG ----> Adding rule $i to the list.\n" if ($debug ne 0);
			}
		}
		else{
			push @rules,$l_value;
			print "DEBUG ----> Adding rule $l_value to the list.\n" if ($debug ne 0);

		}
	}
}


# Retrieving data from configuration file
my $cfg = new Config::Simple('/opt/tufin/securitysuite/ps/perl/api.cfg');

my $st_host = $cfg->param("securetrack.host");
my $st_user = $cfg->param("securetrack.user");
my $st_pass = $cfg->param("securetrack.pass");

my $sc_host = $cfg->param("securechange.host");
my $sc_user = $cfg->param("securechange.user");
my $sc_pass = $cfg->param("securechange.pass");

my $verify_hostname = $cfg->param("ssl.certificate-check");

my $debug_cfg = $cfg->param("debug.level");

if ($debug eq $debug_cfg) {
    $debug = $debug_cfg;
}

#Variable Sanity Check
my $error_code = 0;

# Prepare Rest::Client for SecureTrack
my $st_client = REST::Client->new(host => $st_host);
my $st_encoded_auth = encode_base64("$st_user:$st_pass", '');
$st_client->addHeader( "Authorization", "Basic $st_encoded_auth");
$st_client->addHeader( "Accept", "application/json" );
$st_client->addHeader( "Content-Type", "application/xml");

# Prepare Rest::Client for SecureChange
my $sc_client = REST::Client->new(host => $sc_host);
my $sc_encoded_auth = encode_base64("$sc_user:$sc_pass", '');
$sc_client->addHeader( "Authorization", "Basic $sc_encoded_auth");
$sc_client->addHeader( "Accept", "application/json" );
$sc_client->addHeader( "Content-Type", "application/xml");


## Calculate time for the dates
my ($sec,$min,$hour,$day,$month,$year) = (localtime)[0,1,2,3,4,5];
$year = $year + 1900; #Convert year from 1900
$month = $month + 1; #January is set to 0 so adding 1 to get the real month.

my $job_start_date = "$year-$month-$day $hour:$min:$sec";
#my $end_date_time = add_delta_days($analysis_duration);
my $l_end_month = $month+6;
my $l_end_year = $year;
if ($l_end_month > 12) {
	$l_end_year +=1;
	$l_end_month -= 12;
}
my $job_end_date = "$l_end_year-$l_end_month-$day $hour:$min:$sec";
my $rule_cache = undef;

###############################################################################
#
# Main routine:
#
#
#
###############################################################################

print "DEBUG ----> Initialisation completed, starting main routine.\n" if ($debug ne 0);

if(@{st_db_get_userid($userid)}){
	# We have checked the user and have a valid user to assign the task to.
	my $l_device_id = 0;
	print "INFO  ----> We have a valid user, continuing...\n";
	my $l_device_aref = st_db_get_deviceid_by_name($device_name);
	print "DEBUG ----> Retrieved the device ID lists, now checking if device exists.\n"if ($debug ne 0);
	if (@{$l_device_aref}) {
		for my $l_device (@{$l_device_aref}){
			$l_device_id = $l_device->{'management_id'};
		}
		print "DEBUG ----> We have adevice ID : $l_device_id for name : $device_name.\n" if ($debug ne 0);


                #We are using the Order to calculate the rule.
                while (@rules) {
                        print "DEBUG ----> (main) ----> Looking at rules to generate an APG job for.\n" if ($debug ne 0);
                        my $l_rule_num = shift @rules;
                        my $l_task_name = $l_device_id . "_" . $policy_package . "_" . $l_rule_num;
                        my $l_comment = "APG Job requested via script.";
                        print "INFO  ----> Adding job for rule $l_rule_num.\n";
                        print "DEBUG ----> Calling procedure st_db_add_apg_job.\n" if ($debug ne 0);
                        my $l_result = st_db_add_apg_job(
                                        Task_Name	=> $l_task_name,
                                        Device_Id	=> $l_device_id,
                                        Comment		=> $l_comment,
                                        Start_Date	=> $job_start_date,
                                        End_Date	=> $job_end_date,
                                        Rule_Num	=> $l_rule_num,
                                        Policy		=> $policy_package,
                                        Dst_Zone	=> $to_zone,
                                        Src_Zone	=> $from_zone,
                                        ACL_Name	=> $acl_name,
                                        Rule_Type       => $rule_type
                        );
                }
	}
	else{
		print "ERROR ----> No device found for device name : $device_name\n",
			"Good Bye!\n";
	}
}
else{
	print "ERROR ----> User provided is unknown. Good Bye.\n";
}

my $end_run = time();
my $run_time = $end_run - $start_run;

print "\nINFO\nINFO\n",
    "INFO  ----> Program terminated successfully in : $run_time seconds.\n",
    "\n\n",
    "Good Bye !\n";


###############################################################################
#
# API HELPERS
#

######################################
###### API Helper and sub procedures



sub st_db_add_apg_job{
	#This procedure will insert into the DB a job for a given rule UUID on a given management.
	#
	#INSERT INTO apg_tasks_view (task_name, mgmt_id, phase,  comment, id, end_date, rule_uid, offline, selected_results, policy_name, rule_num, orig_permissiveness, total_hits)
	#VALUES ('test_CGI_APG_create_manual_task', '79', 'added',  'test', 12, '2015-09-02 12:15:32', '9C78C2F3-FBA7-4232-85E6-C456276CC456', 'f', 'f', 'Standard', '1', '79', 0);
	#
	my %l_h_args = @_;
	if ($debug ne 0) {
		print "DEBUG ----> (st_db_add_apg_job) ----> Entered procedure st_db_add_apg_job.\n",
			"DEBUG ----> Procedure parameters are : " . Dumper(%l_h_args);
	}

	my $l_task_name = $l_h_args{Task_Name};
	my $l_comment = $l_h_args{Comment};
	my $l_mgmt_id = $l_h_args{Device_Id};
	my $l_start_date = $l_h_args{Start_Date};
	my $l_end_date = $l_h_args{End_Date};
	my $l_policy_name = $l_h_args{Policy};
	my $l_rule_num = $l_h_args{Rule_Num};
        my $l_rule_type = $l_h_args{Rule_Type};
	my $l_from_zone = $l_h_args{Src_Zone};
	my $l_to_zone = $l_h_args{Dst_Zone};
	my $l_acl_name = $l_h_args{ACL_Name};
	my $l_orig_permissiveness = -1;

	print "DEBUG ----> (st_db_add_apg_job) ----> Calling procedure st_api_get_rule_uuid.\n" if ($debug ne 0);

	my ($l_result,$l_rule_uuid_ref) = st_api_get_rule_uuid(Device_Id => $l_mgmt_id,
					       Rule_Num	=> $l_rule_num,
					       Policy => $l_policy_name,
					       Dst_Zone	=> $l_to_zone,
					       Src_Zone	=> $l_from_zone,
					       ACL_Name => $l_acl_name,
                                               Rule_Type => $l_rule_type
					       );

	#Getting the current last index of the APG tasks.
	my $db_user = "postgres";
	my $db_host = "localhost";
	my $db_name = "securetrack";

	my $dbh = DBI->connect("dbi:Pg:dbname=$db_name", "$db_user","");
	my $sth_rv;
	my $sth = $dbh->prepare("SELECT id,task_name from apg_tasks ORDER BY id DESC");
	$sth->execute() or die "ERROR ----> Error while executing the DB query with message : " . $sth->errstr() . "\n";

	my $ref = $sth->fetchrow_hashref() or die "ERROR ----> Error while fetching the data from DB with message : " . $sth->errstr() . "\n";;
	my $l_highest_task_id = $ref->{'id'};
	my $l_task_id = $l_highest_task_id +1;

	if ($l_result) {
		my $dbquery = "INSERT INTO apg_tasks_view (mgmt_id, task_name, phase,  comment, id, end_date, rule_uid, offline,";
		$dbquery .=  "selected_results, policy_name, rule_num, orig_permissiveness, total_hits)";
		$dbquery .=  "VALUES ('$l_mgmt_id', '$l_task_name', 'added', '$l_comment', $l_task_id, '$l_end_date', '" . $$l_rule_uuid_ref ."', 'f',";
		$dbquery .=  "'f','$l_policy_name', '$l_rule_num', '$l_orig_permissiveness', 0)";

		print "DEBUG ----> (st_db_add_apg_job) ----> dbquery : $dbquery\n" if ($debug ne 0);
		$sth = $dbh->prepare($dbquery);
		$sth_rv = $sth->execute() or die "ERROR ----> Error while executing the DB query at ". __LINE__ . " " . $sth->errstr() . " upon inserting APG job.\n";
		print "DEBUG ----> APG job $l_task_name created, starting them now.\n" if ($debug ne 0);
		st_shell_reconf_mgmt(Device_Id => $l_mgmt_id);
	}
	else{
		print "WARNING ----> Rule #$l_rule_num not found, skipping it.\n";
	}
}

sub st_shell_reconf_mgmt{
	#Procedure that execute the shell script to make sure that the collecting starts.
	my %l_h_args = @_;
	my $l_mgmt_id = $l_h_args{Device_Id};
	if ($debug ne 0) {
		print "DEBUG ----> (st_shell_reconf_mgmt) ----> Entered procedure st_shell_reconf_mgmt.\n",
			"DEBUG ----> Procedure parameters are : " . Dumper(%l_h_args);
	}
	my $output = `/usr/sbin/st reconf $l_mgmt_id`;
	my $l_exitcode = $!;
	my $db_user = "postgres";
	my $db_host = "localhost";
	my $db_name = "securetrack";

	my $dbh = DBI->connect("dbi:Pg:dbname=$db_name", "$db_user","");
	my $sth_rv;
	my $sth = $dbh->prepare("SELECT management_id,management_name,server_id FROM managements WHERE management_id = '$l_mgmt_id'");
	$sth->execute() or die "ERROR ----> (st_shell_reconf_mgmt) ----> Error while executing the DB query with message : " . $sth->errstr() . "\n";

	my $ref = $sth->fetchrow_hashref() or die "ERROR ----> Error while fetching the data from DB with message : " . $sth->errstr() . "\n";
	if ($ref->{server_id} ne 1) {
		$sth = $dbh->prepare("SELECT id,ip,display_name FROM st_servers WHERE id = $ref->{server_id}");
		$sth->execute() or die "ERROR ----> st_shell_reconf_mgmt ----> Error while executing the DB query with message : " . $sth->errstr() . "\n";
		my $l_serverid_ref = $sth->fetchrow_hashref() or die "ERROR ----> st_shell_reconf_mgmt ----> Error while fetching the data from DB with message : " . $sth->errstr() . "\n";
		print "WARNING ----> (st_shell_reconf_mgmt) ----> The device is handled by a distributed server or remote collector.\n",
			"\t\t\t Please run the command 'st reconf $l_mgmt_id' on the server : $l_serverid_ref->{display_name} with IP $l_serverid_ref->{ip}.\ı";
	}
}

sub st_api_get_rule_uuid {
	# This procedure will use the SecureTrack API to collect the rule UUID for a given rule number
	print "DEBUG ----> (st_api_get_rule_uuid) ----> Entered procedure st_api_get_rule_uuid.\n" if ($debug ne 0);
	my %l_h_args = @_;
	my $l_deviceid = $l_h_args{Device_Id};
	my $l_policy = $l_h_args{Policy};
	my $l_rule_num = $l_h_args{Rule_Num};
        my $l_rule_id = $l_h_args{Rule_ID};
	my $l_from_zone = $l_h_args{Src_Zone};
	my $l_to_zone = $l_h_args{Dst_Zone};
	my $l_acl_name = $l_h_args{ACL_Name};
        my $l_rule_type = $l_h_args{Rule_type}; # id, order
	my $l_rule_uid;
	my $l_return_code = -1;

	my $l_request = "/securetrack/api/devices/$l_deviceid";
	$st_client->GET($l_request);
	if ($st_client->responseCode() ne "200") {
		print "ERROR ----> (st_api_get_rule_uuid) ----> Error during API call : error code :"  . $st_client->responseCode() . "\n";
		die;
	}
	my $obj = decode_json ($st_client->responseContent());
	print "DEBUG ----> (st_api_get_rule_uuid) ----> Got device vendor and models -> decoded JSON object : ". Dumper($obj) if ($debug ne 0);
	my $l_device_vendor = $obj->{device}->{vendor};
	my $l_device_model = $obj->{device}->{model};


        if (not defined $rule_cache) {
                $l_request = "/securetrack/api/devices/$l_deviceid/rules";
                print "DEBUG ----> (st_api_get_rule_uuid) ----> Sending GET request to API with : $l_request .\n" if ($debug ne 0);
                $st_client->GET($l_request);
                if ($st_client->responseCode() ne "200") {
                        print "ERROR ----> (st_api_get_rule_uuid) ----> Error during API call : error code :"  . $st_client->responseCode() . "\n";
                        die;
                }
                $obj = decode_json($st_client->responseContent());
                $rule_cache = $obj;
        }
        else{
                $obj = $rule_cache;
        }

	foreach my $l_fw_rule (@{$obj->{rules}->{rule}}){
		my $l_found_rule = 0;
                $l_rule_uid = '';
		print "DEBUG ----> (st_api_get_rule_uuid) ----> Analysing FW rule : " . Dumper($l_fw_rule) if ($debug ne 0);
		if ($l_device_vendor eq "Checkpoint") {
			#code
                        if ($rule_type eq "id") {
                            print "ERROR ----> Checkpoint vendor does not have any rule number, use rule order instead, or leave it empty.\n";
                            print_usage();
                            exit;
                        }

			if ($l_fw_rule->{binding}->{policy}->{name} eq $l_policy) {
				if ($l_fw_rule->{order} eq $l_rule_num) {
					$l_rule_uid = $l_fw_rule->{uid};
					$l_found_rule = 1;
				}
			}
		}
		elsif($l_device_vendor eq "Netscreen"){
			 if ($rule_type eq "id") {
                                if ($l_fw_rule ->{id} eq $l_rule_num) {
                                    $l_rule_uid = $l_fw_rule->{uid};
                                    $l_found_rule = 1;
                                }
                        }
                        elsif ($rule_type eq "number"){
                                if ($l_fw_rule ->{rule_number} eq $l_rule_num) {
                                    $l_rule_uid = $l_fw_rule->{uid};
                                    $l_found_rule = 1;
                                }
                        }
                        else{
                                if (($l_fw_rule->{binding}->{from_zone}->{name} eq $l_from_zone) and
                                    $l_fw_rule->{binding}->{to_zone}->{name} eq $l_to_zone) {
                                        if ($l_fw_rule->{order} eq $l_rule_num) {
                                                $l_rule_uid = $l_fw_rule->{uid};
                                                $l_found_rule = 1;
                                        }
                                }
                        }
		}
		elsif($l_device_vendor eq "Fortinet"){
                        if ($rule_type eq "id") {
                                if ($l_fw_rule ->{id} eq $l_rule_num) {
                                    $l_rule_uid = $l_fw_rule->{uid};
                                    $l_found_rule = 1;
                                }

                        }
                        elsif ($rule_type eq "number"){
                                if ($l_fw_rule ->{rule_number} eq $l_rule_num) {
                                    $l_rule_uid = $l_fw_rule->{uid};
                                    $l_found_rule = 1;
                                }
                        }
                        else{
                                if ($l_from_zone eq "global") {
                                        $l_from_zone = "Any";
                                }
                                if ($l_to_zone eq "global") {
                                        $l_to_zone = "Any";
                                }
                                if (($l_fw_rule->{binding}->{from_zone}->{name} eq $l_from_zone) and
                                    $l_fw_rule->{binding}->{to_zone}->{name} eq $l_to_zone) {
                                        if ($l_fw_rule->{order} eq $l_rule_num) {
                                                $l_rule_uid = $l_fw_rule->{uid};
                                                $l_found_rule = 1;
                                        }
                                }
                        }
		}
		elsif($l_device_vendor eq "Cisco"){
			if ($l_acl_name eq "") {
				print "ERROR ----> You requested analysis for a cisco device without specifying the ACL Name.\n";
				print_usage();
				exit;
			}
			elsif($l_acl_name =~ m/\wlobal/) {
				#We have the Global ACL
				if ($l_fw_rule->{binding}->{acl}->{global} eq "true"){
					if ($l_fw_rule->{order} eq $l_rule_num) {
						$l_rule_uid = $l_fw_rule->{uid};
						$l_found_rule = 1;
					}
				}
			}
			else{
				#We have the local ACL
				if ($l_fw_rule->{binding}->{acl}->{global} eq "true") {
					die "ERROR ----> ACL $l_acl_name has a global statement.\n";
				}
				else{
					if ($l_fw_rule->{binding}->{acl}->{interface}->{acl_name} eq $l_acl_name){
						if ($l_fw_rule->{order} eq $l_rule_num) {
							$l_rule_uid = $l_fw_rule->{uid};
							$l_found_rule = 1;
						}
					}
				}
			}
		}
		elsif($l_device_vendor eq "Stonesoft"){
			die "ERROR ----> Intel Security devices are not supported yet.\n";
		}
		elsif($l_device_vendor eq "PaloAltoNetworks"){
			die "ERROR ----> Palo Alto device are not supported yet.\n";
		}
		else{
			#Unknown Vendor
			die "ERROR ----> Vendor not known.\n";
		}
		if ($l_rule_uid ne '' and $l_found_rule) {
			$l_rule_uid =~ s/\{(.*)\}/$1/;
			print "DEBUG ----> (st_api_get_rule_uuid) ----> Found rule UUID for rule number $l_rule_num : $l_rule_uid\n" if ($debug ne 0);;
			return $l_found_rule,\$l_rule_uid;
		}
	}
}

sub st_db_get_deviceid_by_name{
	# This procedure will retrieve the device management ID
	print "DEBUG ----> (st_db_get_deviceid_by_name) ----> Entered procedure st_db_get_deviceid_by_name.\n" if ($debug ne 0);

	my $l_fw_name = shift;
	my $result = "";
	my $db_user = "postgres";
	my $db_host = "localhost";
	my $db_name = "securetrack";
	my $dbh = DBI->connect("dbi:Pg:dbname=$db_name", "$db_user","");
	my $dbquery = "SELECT management_id,management_name FROM managements WHERE management_name = \'$l_fw_name\'";
	my $sth = $dbh->prepare($dbquery);

	$sth->execute() or die "ERROR ----> (st_db_get_deviceid_by_name) ----> Error while executing the DB query with message : " . $sth->errstr() . "\n";
	my $a_ref = $sth->fetchall_arrayref({});
	return $a_ref;
}

sub st_db_get_userid{
	#This procedure will retrieve check the user ID in the DB
	print "DEBUG ----> (st_db_get_userid) ----> Entered procedure st_db_get_userid.\n" if ($debug ne 0);

	my $st_user = shift;
	my $result = "";
	my $db_user = "postgres";
	my $db_host = "localhost";
	my $db_name = "securetrack";
	my $dbh = DBI->connect("dbi:Pg:dbname=$db_name", "$db_user","");
	my $dbquery = "SELECT user_id,first_name,last_name FROM users WHERE user_id = \'$st_user\'";
	my $sth = $dbh->prepare($dbquery);

	$sth->execute() or die "ERROR ----> Error while executing the DB query with message : " . $sth->errstr() . "\n";
	my $a_ref = $sth->fetchall_arrayref({});
	return $a_ref;
}

#sub add_days{
#
#	my %l_h_args = @_;
#	my $l_date = $l_h_args{Current_Date};
#	my $l_day_to_add = $l_h_args{AddDays};
#	my ($l_sec,$l_min,$l_hour,$l_day,$l_month,$l_year) = (localtime)[0,1,2,3,4,5];
#	$l_year = $l_year + 1900; #Convert year from 1900
#	$l_month = $l_month + 1; #January is set to 0 so adding 1 to get the real month.
#
#	if ($l_days_to_add == 30) {
#		if ($l_month < 12) {
#			$l_month += 1;
#		}
#		else{
#			$l_year += 1;
#			$l_month = 1;
#		}
#	}
#	elsif($l_days_to_add >)
#	#my $end_time = "$l_year-$l_month-$l_day $l_hour:$l_min:$l_sec";
#}

#sub del_days{
#
#}

sub print_usage {
    print "\nHELP has been requested.\n\n Program \t: APG run multiple job script",
        "\n Author  \t: Stephane PEREZ (" . 'stephane.perez@tufin.com'. ")",
        "\n Date \t\t: ".$prog_date."\n\r",
        "\n Version \t: ".$prog_version . "\n\r",
	"\n Usage : apg_batch_run.pl -device-name <management name> [-policy-package <Name of the policy package>]\n",
	"\t\t\t-rule-list <list of rules number>\n",
	"\t\t\t[-rule-type <The type of rule to search : Id, Number, Order>]\n",
	"\t\t\t-duration <number of days for analysis>\n",
	"\t\t\t[-debug ] [-help]\n",
	"Parameters details:\n",
	"\trule-list \t\t : The list of rules on which the user wish to run APG on in the form \n",
	"\t\t\t\t Accepted forms : 1,2-4\n",
	"\t\t\t[-help]\n",
	"Goodbye!\n";
}
