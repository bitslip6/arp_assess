#include <string>
#include <unordered_map>
#include <unordered_set>

#include "nlohmann/json.hpp"
using json = nlohmann::json;



struct Node {
    std::string hostname;
    std::string ip;
    time_t f_time;
    time_t l_time;
    int count;
    int id;

    bool operator==(const Node& other) const {
        return ip == other.ip;
    }
};

struct NodeKeyHash {
    std::size_t operator()(const Node& key) const {
        return (std::hash<std::string>()(key.ip));
    }
};


// Struct for representing edges in the graph
struct Edge {
    std::string target;
    time_t f_time;
    time_t l_time;
    int count;

    bool operator==(const Edge& other) const {
        return target == other.target;
    }
};

struct EdgeKeyHash {
    std::size_t operator()(const Edge& key) const {
        // Combine hashes of individual fields
        return (std::hash<std::string>()(key.target) << 1);
    }
};



bool file_put_contents(const std::string& filename, const std::string& data, bool append = false);
void printGraph(const std::unordered_map<std::string, std::unordered_set<std::string>> &graph);
void handleSignal(int signal);
std::vector<std::string> split(const std::string &line, char delimiter);
std::string generateUniqueID(const std::string& value);
json convertGraphToJSON(const std::unordered_map<Node, std::unordered_set<Edge, EdgeKeyHash>, NodeKeyHash>& graph);