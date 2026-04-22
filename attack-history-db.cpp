#include <iostream>
#include <fstream>
#include <string>
#include <vector>
using namespace std;

struct AttackEvent {
    string timestamp;
    string actor;
    string type;
    string description;
};

void logAttackEvent(const AttackEvent &e, const string &filename = "attack-history-db.txt") {
    ofstream file(filename, ios::app);
    if (!file.is_open()) {
        cerr << "Error opening attack history database file.\n";
        return;
    }
    file << e.timestamp << "|" << e.actor << "|" << e.type << "|" << e.description << "\n";
    file.close();
}

vector<AttackEvent> readAttackHistory(const string &filename = "attack-history-db.txt") {
    vector<AttackEvent> events;
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error opening attack history database file.\n";
        return events;
    }

    string line;
    while (getline(file, line)) {
        size_t p1 = line.find("|");
        size_t p2 = line.find("|", p1 + 1);
        size_t p3 = line.find("|", p2 + 1);

        if (p1 != string::npos && p2 != string::npos && p3 != string::npos) {
            AttackEvent e;
            e.timestamp = line.substr(0, p1);
            e.actor = line.substr(p1 + 1, p2 - p1 - 1);
            e.type = line.substr(p2 + 1, p3 - p2 - 1);
            e.description = line.substr(p3 + 1);
            events.push_back(e);
        }
    }
    file.close();
    return events;
}

void printAttackHistory(const vector<AttackEvent> &events) {
    cout << "Time\tActor\tType\tDescription\n";
    for (const auto &e : events) {
        cout << e.timestamp << "\t" << e.actor << "\t" << e.type << "\t" << e.description << "\n";
    }
}

int main() {

    auto history = readAttackHistory();
    printAttackHistory(history);
    return 0;
}
