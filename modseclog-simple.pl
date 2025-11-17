#!/usr/bin/perl

use strict;
use warnings;

# --- Configuration ---
my $LOG_FILE = shift @ARGV;
my $MAX_URI_LENGTH = 45; # Define the maximum display length for the URI column

# Check if a log file was provided
unless ($LOG_FILE) {
    print "Usage: $0 /path/to/modsec_audit.log\n";
    exit 1;
}

# --- Core Logic ---

# Check if the file exists and is readable
unless (-e $LOG_FILE && -r $LOG_FILE) {
    die "Error: Cannot read log file '$LOG_FILE'. Check path and permissions.\n";
}

open(my $fh, '<', $LOG_FILE) or die "Could not open $LOG_FILE: $!\n";

my $result_count = 0;
my $current_entry = "";
my $in_transaction = 0; # Flag to track if we are inside a transaction block
my $transaction_id = ""; # Variable to store the unique transaction ID

# --- Adjusted Header: Added Transaction ID ---
print "-----------------------------------------------------------------------------------------------------------------------------\n";
print " ModSecurity Audit Log Analysis (Streaming Mode - Resilient to Section Order)\n";
print "-----------------------------------------------------------------------------------------------------------------------------\n";
printf "%-10s | %-15s | %-25s | %-45s | %s\n", "Trans ID", "Source IP", "Domain/Host", "Requested URI", "Rule ID";
print "-----------------------------------------------------------------------------------------------------------------------------\n";


# Loop through the log file line by line
while (my $line = <$fh>) {
    
    # Check for the start of a new transaction (--BOUNDARY-A--)
    if ($line =~ /^--(\S+)-A--/) {
        $transaction_id = $1; # Capture the transaction ID
        # Reset and start buffering a new transaction
        $in_transaction = 1;
        $current_entry = $line;
    } 
    elsif ($in_transaction) {
        # Append line to the current buffer
        $current_entry .= $line;

        # Check for the end of the transaction (--BOUNDARY-Z--)
        if ($line =~ /^--(\S+)-Z--\s*$/) {
            
            # --- Transaction block is complete. Now extract data using separate, resilient regexes. ---
            
            my ($ip, $domain, $uri, $rule_id, $rule_msg);

            # 1. Extract Source IP from Part A (Mandatory)
            # This regex is specific to the log line format: [Timestamp] UniqueID SourceIP SourcePort DestIP DestPort
            # It explicitly skips the first two tokens and captures the third (Source IP).
            if ($current_entry =~ /^--\S+-A--\s*\n.*?\[[^\]]+\]\s+[^ ]+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*?\n/msi) {
                $ip = $1;
            }
            
            # 2. Extract Host and URI from Part B (Mandatory)
            # Regex looks for the Host: header anywhere within the entry after Part B starts
            if ($current_entry =~ /^--\S+-B--.*?\n.*?Host:\s*([^\s\r\n]+)/msi) {
                $domain = $1;
            }
            # Extract the requested URI (second token on the request line in Part B)
            if ($current_entry =~ /^--\S+-B--\s*\n\s*[^ ]+\s+([^\s\r\n]+)/msi) {
                $uri = $1;
            }

            # 3. Extract Rule ID and Message from Part H (Optional)
            # Initialize optional fields
            $rule_id = "";

            # 3a. Extract Rule ID (can appear anywhere after --H--)
            # Looks for the [id ""] tag anywhere after the --H-- boundary.
            if ($current_entry =~ /^--\S+-H--.*?\[id\s+"(\d+)"\]/msi) {
                $rule_id = $1;
            }
            
            # Print logic is now less strict: only require IP, Host, and URI to print
            if ($ip && $domain && $uri) {
                
                # --- URI Truncation Logic ---
                my $uri_display;
                if (length($uri) > $MAX_URI_LENGTH) {
                    # Truncate and append '...' to fit the 45 character width
                    $uri_display = substr($uri, 0, $MAX_URI_LENGTH - 3) . '...';
                } else {
                    $uri_display = $uri;
                }
                # -----------------------------

                # Prepare display variables, using placeholders if rule data is missing
                my $rule_id_display = $rule_id || "N/A";
                
                # Print the extracted data, including the transaction ID
                printf "%-10s | %-15s | %-25s | %-45s | %s\n", $transaction_id, $ip, $domain, $uri_display, $rule_id_display;
                $result_count++;
            } 
            
            # Reset for the next entry
            $in_transaction = 0;
            $current_entry = "";
            $transaction_id = "";
        }
    }
}

close($fh);

print "-----------------------------------------------------------------------------------------------------------------------------\n";
print "Total transactions analyzed: $result_count\n";

if ($result_count == 0) {
    print "No ModSecurity transaction records found in the specified format.\n";
}

exit 0;

