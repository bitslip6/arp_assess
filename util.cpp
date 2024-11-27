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

// Function to generate a unique ID for each node
std::string generateUniqueID(const std::string& value) {
    static size_t counter = 0;
    return value + "_" + std::to_string(++counter);
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

// Main conversion function
json convertGraphToJSON(const std::unordered_map<Node, std::unordered_set<Edge, EdgeKeyHash>, NodeKeyHash>& graph) {
    json result;
    result["comment"] = "network graph of DNS requests";
    
    json nodes = json::array();
    json edges = json::array();
    
    // Maps to store unique IDs for nodes
    std::unordered_map<std::string, std::string> nodeIDMap;
    
    // Process nodes and edges
    for (const auto& [sourceNode, edgeSet] : graph) {
        // Generate unique ID for the source node's IP if not already added
        const std::string& sourceIP = sourceNode.ip;
        if (nodeIDMap.find(sourceIP) == nodeIDMap.end()) {
            std::string sourceID = generateUniqueID(sourceIP);
            nodeIDMap[sourceIP] = sourceID;
            nodes.push_back({
                {"caption", sourceIP},
                {"type", "host"},
                {"id", sourceID}
            });
        }
        
        // Iterate over the edges connected to the source node
        for (const auto& edge : edgeSet) {
            const std::string& targetDomain = edge.target;
            // Add target node if not already added
            if (nodeIDMap.find(targetDomain) == nodeIDMap.end()) {
                std::string targetID = generateUniqueID(targetDomain);
                nodeIDMap[targetDomain] = targetID;
                nodes.push_back({
                    {"caption", targetDomain},
                    {"type", "lookup"},
                    {"id", targetID}
                });
            }
            
            // Add edge with additional edge attributes if needed
            edges.push_back({
                {"source", nodeIDMap[sourceIP]},
                {"target", nodeIDMap[targetDomain]},
                {"caption", "lookup"},
                {"count", edge.count},
                {"first_time", edge.f_time},
                {"last_time", edge.l_time}
            });
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

