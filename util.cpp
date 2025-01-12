#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <algorithm>
#include <functional>
#include <optional>
#include <csignal>
#include <unistd.h>
#include <time.h>

#include "nlohmann/json.hpp"
using json = nlohmann::json;

#include  "util.h"


extern std::unordered_map<Node, std::unordered_set<Edge, EdgeKeyHash>, NodeKeyHash> graph;
extern std::unordered_set<std::string> malware;
extern std::unordered_set<std::string> million;

// Function to generate a unique ID for each node
std::string generateUniqueID(const std::string& value) {
    static size_t counter = 0;
    return value + "_" + std::to_string(++counter);
}


void replace_dots_with_underscores(char* str) {
    // Iterate through each character in the string
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == '.') {
            str[i] = '_'; // Replace dot with underscore
        }
    }
}


void replace_dots_with_underscores_str(std::string& str) {
    std::replace(str.begin(), str.end(), '.', '_');
}



// Function to split a string based on a delimiter
std::vector<std::string> split(const std::string &line, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(line);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

/**
 * write a string to a file
 */
bool file_put_contents(const std::string& filename, const std::string& data, bool append) {
    // Choose the mode: append to the file or overwrite
    std::ios::openmode mode = std::ios::out;
    if (append) {
        mode |= std::ios::app;
    }

    // Open the file with the specified mode
    std::ofstream file(filename, mode);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << " for writing!" << std::endl;
        return false;
    }

    // Write data to the file
    file << data;

    // Close the file
    file.close();

    // Check for write errors
    if (file.fail()) {
        std::cerr << "Error: Failed to write to file " << filename << "!" << std::endl;
        return false;
    }

    return true;
}


// Function to print the graph for visualization
void printGraph(const std::unordered_map<std::string, std::unordered_set<std::string>> &graph) {
    for (const auto &[source, targets] : graph) {
        std::cout << source << " -> ";
        for (const auto &target : targets) {
            std::cout << target << " ";
        }
        std::cout << std::endl;
    }
}

// Function to extract the domain and TLD from an FQDN
char* extract_domain(char* fqdn) {
    // Copy the input FQDN to a mutable buffer
    static char domain[256]; // Static to ensure the buffer persists outside the function
    strncpy(domain, fqdn, sizeof(domain) - 1);
    domain[sizeof(domain) - 1] = '\0'; // Null-terminate to avoid overflow

    // Tokenize the FQDN by splitting on dots
    char* token = strtok(domain, ".");
    char* prev = NULL; // The last part of the domain
    char* second_last = NULL; // The second last part of the domain

    // Iterate through the tokens
    while (token != NULL) {
        second_last = prev; // Update the second-to-last domain part
        prev = token;       // Update the last domain part
        token = strtok(NULL, ".");
    }

    // Check if we have at least two parts (domain and TLD)
    if (prev && second_last) {
        // Concatenate second_last and prev into the result buffer
        snprintf(domain, sizeof(domain), "%s.%s", second_last, prev);
        return domain;
    }

    // If the input doesn't have at least a domain and TLD, return the original FQDN
    return fqdn;
}



// Main conversion function
json convertGraphToJSON(const std::unordered_map<Node, std::unordered_set<Edge, EdgeKeyHash>, NodeKeyHash>& graph) {
    json result;
    result["comment"] = "network graph of DNS requests";
    
    json nodes = json::array();
    json edges = json::array();
    
    // Maps to store unique IDs for nodes
    std::unordered_map<std::string, std::string> nodeIDMap;
    time_t now;
    time(&now);
    
    // Process nodes and edges
    for (const auto& [sourceNode, edgeSet] : graph) {
        // Generate unique ID for the source node's IP if not already added
        const std::string& sourceIP = sourceNode.ip;
        if (nodeIDMap.find(sourceIP) == nodeIDMap.end()) {
            std::string sourceID = generateUniqueID(sourceIP);
            replace_dots_with_underscores_str(sourceID);
            nodeIDMap[sourceIP] = sourceID;
            std::string type = "host";
            if (strstr(sourceIP.c_str(), "10.80") != NULL) {
                type = "host";
            } else {
                type = "target";
            }

            nodes.push_back({
                {"caption", sourceIP},
                {"type", type},
                {"id", sourceID}
            });
        }
        
        // Iterate over the edges connected to the source node
        for (const auto& edge : edgeSet) {
            const std::string& targetDomain = edge.target;
            // Add target node if not already added
            if (nodeIDMap.find(targetDomain) == nodeIDMap.end()) {
                std::string targetID = generateUniqueID(targetDomain);
                replace_dots_with_underscores_str(targetID);
                nodeIDMap[targetDomain] = targetID;

                std::string type = "target";
                std::string domain_only = std::string(extract_domain((char*)targetDomain.c_str()));
                printf(" -- checking %s\n", domain_only.c_str());
                if (malware.find(domain_only) != malware.end()) {
                    std::cout << " ! ! found malware domain: " << domain_only.c_str() << std::endl;
                    type = "malware";
                } else if (million.find(domain_only) != million.end()) {
                    std::cout << " + + found million domain: " << domain_only.c_str() << std::endl;
                    type = "top";
                }

                nodes.push_back({
                    {"caption", targetDomain},
                    {"type", type},
                    {"root", 1},
                    {"id", targetID}
                });
            }
            
            // Add edge with additional edge attributes if needed
	    time_t diff = now - edge.l_time;
	    // only show last hour of dns lookups
	    if (diff < 3600) {
		    char buff[250];
		    sprintf(buff, "#:%d, @%ld", edge.count, diff);


            std::string type = "lookup";
            if (strstr(targetDomain.c_str(), "10.80") != NULL) {
                type = "internal lookup";
            } else {
                std::string domain_only = std::string(extract_domain((char*)targetDomain.c_str()));
                trim_whitespace(domain_only);
                printf("checking %s = %s\n", targetDomain.c_str(), domain_only.c_str());
                if (malware.find(domain_only) != malware.end()) {
                    std::cout << " ! ! found malware domain: " << domain_only << std::endl;
                    type = "malware";
                } else if (million.find(domain_only) != million.end()) {
                    std::cout << " + + found million domain: " << domain_only << std::endl;
                    type = "top";
                }
            }


            std::string sip1 = nodeIDMap[sourceIP];
            std::string tdm1 = nodeIDMap[targetDomain];

            replace_dots_with_underscores_str(sip1);
            replace_dots_with_underscores_str(tdm1);

		    edges.push_back({
			{"source", sip1},
			{"target", tdm1},
            {"type", type}, 
			{"caption", buff},
			{"count", edge.count},
			{"first_time", edge.f_time},
			{"last_time", edge.l_time}
		    });
	    }
        }
    }
    
    result["nodes"] = nodes;
    result["edges"] = edges;
    return result;
}

// Main conversion function
json convertGraphToJSON_old(const std::unordered_map<std::string, std::unordered_set<std::string>>& graph) {
    json result;
    result["comment"] = "network graph of DNS requests";
    
    json nodes = json::array();
    json edges = json::array();
    
    // Maps to store unique IDs for nodes
    std::unordered_map<std::string, std::string> nodeIDMap;
    
    // Process nodes and edges
    for (const auto& [source, targets] : graph) {
        // Add source node if not already added
        if (nodeIDMap.find(source) == nodeIDMap.end()) {
            std::string sourceID = generateUniqueID(source);
            nodeIDMap[source] = sourceID;
            nodes.push_back({{"caption", source}, {"type", "host"}, {"id", sourceID}});
        }
        
        for (const auto& target : targets) {
            // Add target node if not already added
            if (nodeIDMap.find(target) == nodeIDMap.end()) {
                std::string targetID = generateUniqueID(target);
                nodeIDMap[target] = targetID;
                nodes.push_back({{"caption", target}, {"type", "lookup"}, {"id", targetID}});
            }
            
            // Add edge
            edges.push_back({
                {"source", nodeIDMap[source]},
                {"target", nodeIDMap[target]},
                {"caption", "lookup"}
            });
        }
    }
    
    result["nodes"] = nodes;
    result["edges"] = edges;
    return result;
}




void trim_whitespace(std::string& str) {
    // Remove all whitespace characters (spaces, tabs, newlines, etc.)
    str.erase(std::remove_if(str.begin(), str.end(), [](unsigned char ch) {
        return std::isspace(ch);
    }), str.end());
}