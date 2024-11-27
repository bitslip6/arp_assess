#!/bin/bash
#
# list of abuse domains
# urlhaus_domain.txt
# stalkerware_domain.txt
# spam404_domain.txt
# phishing_army_domain.txt
# firebog_phishing_domain.txt
# notrack_malware_domain.txt
# firebog_malware_domain.txt
# dns_blacklists_domain.txt
# fademind_domain.txt
# crypto_domain.txt
# digitalside_domain.txt
# antimalware_domain.txt

# pull out domains that are preferenced with an ip address
extract_ip_domains() {
    local input_file="$1"
    local output_file="$2"
    if [[ ! -f "$input_file" ]]; then
        echo "Error: Input file '$input_file' does not exist."
        return 1
    fi
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$input_file" | awk '{print $2}' > "$output_file"
    echo "Domains have been extracted to $output_file"
    return 0
}

# pull out domains that are preferenced with || and end in ^ or have a comment
extract_regex_domains() {
    # Parameters: input file and output file
    local input_file="$1"
    local output_file="$2"

    # Ensure input file exists
    if [[ ! -f "$input_file" ]]; then
        echo "Error: Input file '$input_file' does not exist."
        return 1
    fi

    # Process the file:
    # 1. Remove lines starting with '#'
    # 2. Remove '||' and '$' from lines
    grep -vE '^#' "$input_file" | sed 's/||//g; s/\$//g; s/\^$//;' > "$output_file"

    # Print success message
    echo "Processed lines have been written to $output_file"
    return 0
}


# pull out domains that are preferenced with || and end in ^ or have a comment
extract_space_hash_domains() {
    # Parameters: input file and output file
    local input_file="$1"
    local output_file="$2"

    # Ensure input file exists
    if [[ ! -f "$input_file" ]]; then
        echo "Error: Input file '$input_file' does not exist."
        return 1
    fi

    # Process the file:
    # 1. Remove lines starting with '#'
    # 2. Remove '||' and '$' from lines
    grep -vE '^#' "$input_file" | sed 's/[ #].*//g;' > "$output_file"

    # Print success message
    echo "Processed lines have been written to $output_file"
    return 0
}



file_modified_2_days_ago() {
    local file="$1"

    # Check if the file exists
    if [[ ! -f "$file" ]]; then
        echo "File does not exist."
        return 0
    fi

    # Check if the file was modified more than 2 days ago
    if [[ $(find "$file" -mtime +2 -print) ]]; then
        return 0  # File exists and was modified more than 2 days ago
    else
        return 1  # File exists but was modified within the last 2 days
    fi
}


# url haus download and process
if file_modified_2_days_ago urlhaus.txt; then
	echo "updating urlhaus data"
	curl https://urlhaus.abuse.ch/downloads/hostfile/ -o urlhaus.txt
	extract_ip_domains urlhaus.txt urlhaus_domain.txt
fi

# stalker ware
if file_modified_2_days_ago stalkerware_domain.txt; then
	echo "updating stalkerware data"
	curl https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts -o stalkerware_domain.txt
fi

# spam404
if file_modified_2_days_ago spam404_domain.txt; then
	echo "updating spam404 data"
	curl https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt -o spam404_domain.txt
fi

# firebog phishing
if file_modified_2_days_ago firebog_phishing.txt; then
	echo "updating firebog phishing data"
	curl https://v.firebog.net/hosts/RPiList-Phishing.txt -o firebog_phishing.txt
	extract_regex_domains firebog_phishing.txt firebog_phishing_domain.txt
fi


# firebog malware
if file_modified_2_days_ago firebog_malware.txt; then
	echo "updating firebog malware data"
	curl https://v.firebog.net/hosts/RPiList-Malware.txt -o firebog_malware.txt
	extract_regex_domains firebog_malware.txt firebog_malware_domain.txt
fi

# notrack malware
if file_modified_2_days_ago notrack_malware.txt; then
	echo "updating notrack malware data"
	curl https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt -o notrack_malware.txt
	extract_space_hash_domains notrack_malware.txt notrack_malware_domain.txt
fi

# phishing army blocklist
if file_modified_2_days_ago phishing_army.txt; then
	echo "updating phishing army data"
	curl https://phishing.army/download/phishing_army_blocklist_extended.txt -o phishing_army.txt
	extract_space_hash_domains phishing_army.txt phishing_army_domain.txt
fi

# phishing army blocklist
if file_modified_2_days_ago dns_blacklists_domain.txt; then
	echo "updating phishing army data"
	curl https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt -o dns_blacklists_domain.txt
fi


# fademind download and process
if file_modified_2_days_ago fademind.txt; then
	echo "updating fademind data"
	curl https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts -o fademind.txt
	extract_ip_domains fademind.txt fademind_domain.txt
fi


# fademind download and process
if file_modified_2_days_ago crypto_domain.txt; then
	echo "updating crypto data"
	curl https://v.firebog.net/hosts/Prigent-Crypto.txt -o crypto.txt
    	grep -vE '^#' "crypto.txt" | sed 's/0.0.0.0//g;' > "crypto_domain.txt"
fi


# osint digitalside and process
if file_modified_2_days_ago digitalside_domain.txt; then
	echo "updating digitalside data"
	curl https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt -o digitalside.txt
	extract_ip_domains digitalside.txt digitalside_domain.txt
fi


# antimalware list and process
if file_modified_2_days_ago antimalware_domain.txt; then
	echo "updating antimalware data"
	curl https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt -o antimalware.txt
	extract_ip_domains antimalware.txt antimalware_domain.txt
fi

cat *_domain.txt > fulldomain.txt
sort -u fulldomain.txt > block.txt
