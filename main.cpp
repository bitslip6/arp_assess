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
#include "util.h"

using json = nlohmann::json;



// std::unordered_set<Node> hosts;
std::unordered_map<Node, std::unordered_set<Edge, EdgeKeyHash>, NodeKeyHash> graph;


// Function to parse a single dnsmasq log line
std::optional<Edge> parseLogLine(const std::string &line) {
    auto tokens = split(line, ' ');
    // std::cout << "sz: " << tokens.size() << ", 4: " << tokens[4] << ", 5: " << tokens[5] << std::endl;
    if (tokens.size() < 8 ||  tokens[4] != "query[A]") {
        return std::nullopt;
    }

    // Extract the queried domain and the source IP
    std::string domain = tokens[5];
    // std::cout << "found domain: " << domain <<  " ... " << tokens[7] << std::endl;
    std::string sourceIP = tokens[7];

    time_t now;
    time(&now);

    Edge new_edge = Edge{domain, now, now, 1};
    Node check_node = Node{domain, sourceIP, now, now, 1};
    auto it_node = graph.find(check_node);
    if (it_node != graph.end()) {
        std::cout << "Found node: " << std::endl;
        auto& edge_set = it_node->second;
        auto it_edge = edge_set.find(new_edge);
        if (it_edge != edge_set.end()) {
            std::cout << "Found edge: " << std::endl;
            Edge check_edge = *it_edge;
            edge_set.erase(it_edge);
            check_edge.count++;
            check_edge.l_time = now;
            edge_set.insert(check_edge);
            return check_edge;
        } else {
            std::cout << "No Edge found!" << std::endl;
            edge_set.insert(new_edge);
        }
    } else {
        std::cout << "No Node found!" << std::endl;
        graph.insert({check_node, {new_edge}});
    }
    return new_edge;
}


// Main conversion function
json convertGraphToJSON(const std::unordered_map<std::string, std::unordered_set<std::string>>& graph) {
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

// Signal handler function
void handleSignal(int signal) {
    if (signal == 10) {
	    auto json_data = convertGraphToJSON(graph);
        auto json_string = json_data.dump(4);
        if (file_put_contents("netmap.json", json_string, false)) {
            std::cout << " + wrote new netmap.json" << std::endl;
        } else {
            std::cout << " + unable to write new netmap.json" << std::endl;
        }
    } else {
        std::cout << "Received unknown signal: " << signal << std::endl;
    }
}


int main() {

    if (signal(SIGUSR1, handleSignal) == SIG_ERR) {
        std::cerr << "Error: Unable to set SIGUSR1 handler!" << std::endl;
        exit(0);
    } else {
        std::cout << "SIGUSR1 handler is set up. Send SIGUSR1 to this process to trigger the handler." << std::endl;
    }

    try {
        // Malware domains (this would normally be loaded from a file or database)
        std::unordered_set<std::string> malwareDomains = {"malicious.com", "phishing.net", "malware-site.org"};

        // Log file path
        std::string logFile = "/var/log/dnsmasq.log";


        std::ifstream pipeStream;

        // Open the UNIX pipe for reading from standard input
        pipeStream.open(logFile);
        if (!pipeStream.is_open()) {
            std::cerr << "Failed to open pipe." << std::endl;
            return 1;
        }

        std::string logLine;
        while (true) {
            // Read a line of text from the pipe
            if (std::getline(pipeStream, logLine)) {
                // std::cout << " logline: " << logLine << std::endl;

                // Pass the line to the parsing function
                auto edgeOpt = parseLogLine(logLine);
                if (edgeOpt) {
                    Edge edge = edgeOpt.value();
                    //graph[edge.source].insert(edge.target);
                    std::cout  << " TARGET: " << edge.target << std::endl;
                }
            } else if (pipeStream.eof()) {
                // Handle EOF: Reopen the pipe for new input
                pipeStream.clear(); // Clear EOF state
                pipeStream.seekg(0, std::ios::beg); // Reset stream position
            } else {
                std::cerr << "Error reading from pipe." << std::endl;
                break;
            }
        }


	    //std::cout << "building graph\n";
        // Build the graph
        // auto graph = buildGraph(logFile, malwareDomains);

        // Print the graph
        //printGraph(graph);

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

