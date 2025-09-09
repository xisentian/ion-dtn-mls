// Version 13.0
/*
This version intended for use with testing scripts.
It will accept either 1 or two arguments. Originator passes only source EID (ipn:1.1).
Joiners pass source EID (ipn:node.1) and dest EID (ipn:1.1).

This version is written to leverage the advantages of MLS. Once the group is formed,
subordinates create an update proposal, commit it, and then send that commit to the leader.
The leader broadcasts the commit to the other subordinates. All who receive the commit
handle it. Ideally because every member commits, future commits should grow logarithmicly.

Removed from this version is any functionality regarding removing members, or
adding additional members once the group is formed.
*/

// Compilation Instruction
/*
g++ mls_in_line_v13.cpp -o mls_in_line_v13 \
    -I/home/ubuntu/Desktop/mlspp/mlspp/include/ \
    -I/home/ubuntu/Desktop/mlspp/mlspp/lib/bytes/include/ \
    -I/home/ubuntu/Desktop/mlspp/mlspp/lib/tls_syntax/include \
    -I/home/ubuntu/Desktop/mlspp/mlspp/lib/hpke/include \
    -I/home/ubuntu/Desktop/mlspp/mlspp/build \
    -I/home/ubuntu/Desktop/mlspp/mlspp/vcpkg/packages/openssl_x64-linux/include/openssl \
    -L/home/ubuntu/Desktop/mlspp/mlspp/vcpkg/packages/openssl_x64-linux/lib \
    -L/home/ubuntu/Desktop/mlspp/mlspp/build/lib/bytes \
    -L/home/ubuntu/Desktop/mlspp/mlspp/build/lib/tls_syntax \
    -L/home/ubuntu/Desktop/mlspp/mlspp/build/lib/hpke \
    -L/home/ubuntu/Desktop/mlspp/mlspp/build \
    -lbp -lpthread -lici -lmlspp -lbytes -lhpke -ltls_syntax -lssl -lcrypto -ldl
*/

// Libraries
#include <cstring>
#include <csignal>
#include <iostream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <optional>
#include <sys/types.h>
#include <mutex>
#include <cstdlib>
#include <unistd.h>
#include <thread>
#include <sys/resource.h>

// ION/BP Libraries
extern "C" {
#include "bp.h"        // ION BP API (bp_attach, bp_open, bp_send, bp_receive, etc.)
#include "ionsec.h"    // ionsecadmin API
}

// MLS Libraries
#include <mls/session.h>      // MLS++ high-level Session API
#include <mls/crypto.h>       // Key generation and cryptographic types
#include <mls/credential.h>   // Credential (identity) types
#include <mls/messages.h>
#include <tls/tls_syntax.h>   // for marshal and get

// Constants
constexpr uint8_t KP = 0x00;
constexpr uint8_t WELCOME = 0x01;
constexpr uint8_t PROPOSAL = 0x02;
constexpr uint8_t COMMIT = 0x03;

const mls::CipherSuite SUITE {mls::CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519};

// Global variables for BP SAP handles and control flags
static BpSAP  sap_receive = NULL;
static BpSAP  sap_send    = NULL;
static bool keyAdded = false;
static Sdr    sdr;                                    // Handle to ION's SDR (BP data store)
static const char *sourceEid = NULL;                  // Local source EID (e.g., "ipn:1.1")
static const char *destEid   = NULL;                  // Destination EID to send bundles to
static volatile bool running = true;                  // Control flag to stop threads gracefully
static std::optional<mls::PendingJoin> client_join;
static std::optional<mls::Session> session;
static std::optional<mls::Client> client;
static std::vector<bytes> pendingKeyPackages;
static std::vector<mls::bytes_ns::bytes> pendingProposals;
static std::vector<std::string> pendingProposers;
static std::vector<std::string> pendingJoiners;
static std::vector<std::string> activeGroupMembers;
static std::vector<std::string> thresholdCounter;
static int groupThreshold = 2;                       // Default, will be updated by argv[1]
static int commitCounter = 2;

// Signal handler to gracefully shut down on Ctrl-C (SIGINT)
void handle_sigint(int sig) {
    (void)sig;
    running = false;
    if (sap_receive != NULL) {
        bp_interrupt(sap_receive);  // Interrupt any blocking bp_receive call
    }
}

// Returns timestamp string for use in debugging or logging.
std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm* local_tm = std::localtime(&now_c);

    std::ostringstream oss;
    oss << std::put_time(local_tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

inline const char* mls_type_name(uint8_t t) {
  switch (t) {
    case KP:       return "KP";
    case WELCOME:  return "WELCOME";
    case PROPOSAL: return "PROPOSAL";
    case COMMIT:   return "COMMIT";
    default:       return "UNKNOWN";
  }
}

inline std::mutex& mls_log_mutex() {
  static std::mutex m;
  return m;
}

inline void mls_log_text(const std::string& msg) {
  std::lock_guard<std::mutex> lk(mls_log_mutex());
  std::ofstream lf("mlslog.txt", std::ios::app);
  if (lf.is_open()) {
    lf << "[" << currentTimestamp() << "] " << msg << "\n";
  }
}

inline void mls_log_recv(const char* type, size_t bytes, const char* from) {
  mls_log_text(std::string("RECV type=") + type + " bytes=" + std::to_string(bytes) + " from=" + from);
}

inline void mls_log_send(const char* type, size_t bytes, const std::string& to) {
  mls_log_text(std::string("SEND type=") + type + " bytes=" + std::to_string(bytes) + " to=" + to);
}

struct MlsOpStart {
  std::string ts;
  std::chrono::high_resolution_clock::time_point t0;
  rusage ru0{};
};

// BEGIN line + start snapshots
inline MlsOpStart mls_begin_op(const char* label) {
  MlsOpStart s;
  s.ts = currentTimestamp();
  getrusage(RUSAGE_SELF, &s.ru0);
  s.t0 = std::chrono::high_resolution_clock::now();
  mls_log_text(std::string("BEGIN ") + label);
  return s;
}

// END snapshot -> CSV row + END line
// CSV: timestamp,wall_ms,user_ms,sys_ms,peak_rss_kb,peak_rss_delta_kb,cpu_pct,sourceEID,action
inline void mls_write_metrics(const char* action,
                              const MlsOpStart& s,
                              const char* sourceEid) {
  rusage ru1{};
  getrusage(RUSAGE_SELF, &ru1);
  auto t1 = std::chrono::high_resolution_clock::now();

  double wall_ms = std::chrono::duration<double, std::milli>(t1 - s.t0).count();
  double user_ms = (ru1.ru_utime.tv_sec - s.ru0.ru_utime.tv_sec) * 1000.0 +
                   (ru1.ru_utime.tv_usec - s.ru0.ru_utime.tv_usec) / 1000.0;
  double sys_ms  = (ru1.ru_stime.tv_sec - s.ru0.ru_stime.tv_sec) * 1000.0 +
                   (ru1.ru_stime.tv_usec - s.ru0.ru_stime.tv_usec) / 1000.0;
  double cpu_pct = wall_ms > 0.0 ? ((user_ms + sys_ms) / wall_ms) * 100.0 : 0.0;

  long peak_rss_after_kb = ru1.ru_maxrss;
  long peak_rss_delta_kb = peak_rss_after_kb - s.ru0.ru_maxrss;
  if (peak_rss_delta_kb < 0) peak_rss_delta_kb = 0;

  {
    std::lock_guard<std::mutex> lk(mls_log_mutex());
    std::ofstream csv("mls_metrics.csv", std::ios::app);
    if (csv.is_open()) {
      csv << s.ts << ","
          << wall_ms << ","
          << user_ms << ","
          << sys_ms << ","
          << peak_rss_after_kb << ","
          << peak_rss_delta_kb << ","
          << cpu_pct << ","
          << sourceEid << ","
          << action << "\n";
    }
  }

  mls_log_text(std::string("END ") + action +
               " dur_ms=" + std::to_string(wall_ms) +
               " user_ms=" + std::to_string(user_ms) +
               " sys_ms=" + std::to_string(sys_ms) +
               " peak_rss_kb(after)=" + std::to_string(peak_rss_after_kb) +
               " peak_rss_delta_kb=" + std::to_string(peak_rss_delta_kb) +
               " cpu%=" + std::to_string(cpu_pct));
}

// For deriving node number from EID.
static int extract_ipn_node(const std::string& eid) {
    const std::string prefix = "ipn:";
    if (eid.rfind(prefix, 0) != 0) return -1;
    const auto dot = eid.find('.', prefix.size());
    if (dot == std::string::npos) return -1;
    const auto num_str = eid.substr(prefix.size(), dot - prefix.size());
    try {
        return std::stoi(num_str);
    } catch (...) {
        return -1;
    }
}

// Converts hex to raw bytes.
bytes hexBytesToRawBytes(const bytes& hexBytes) {
    if (hexBytes.size() % 2 != 0) {
        throw std::invalid_argument("Hex byte array must have even length");
    }

    bytes raw;
    raw.reserve(hexBytes.size() / 2);

    for (size_t i = 0; i < hexBytes.size(); i += 2) {
        char high = std::tolower(static_cast<char>(hexBytes.data()[i]));
        char low  = std::tolower(static_cast<char>(hexBytes.data()[i + 1]));

        if (!std::isxdigit(high) || !std::isxdigit(low)) {
            throw std::invalid_argument("Invalid hex digit in input");
        }

        std::string byteStr{high, low};
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
        raw.push_back(byte);
    }

    return raw;
}

// Invisibly runs script.
void runScriptInBackground(const std::string& scriptPath) {
    pid_t pid = fork();

    if (pid < 0) {
        std::cerr << "Fork failed\n";
        return;
    }

    if (pid == 0) {
        // Child process
        setsid();

        // Run the script
        execl("/bin/bash", "bash", scriptPath.c_str(), (char*)nullptr);

        // If execl fails
        std::cerr << "execl failed\n";
        exit(1);
    }
}

// Converts MLS messages to hex string format. Used in debugging/logging.
bytes toHexBytes(const bytes& data) {
    bytes hex;
    hex.reserve(data.size() * 2);

    for (uint8_t byte : data) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", byte);
        hex.push_back(static_cast<uint8_t>(buf[0]));
        hex.push_back(static_cast<uint8_t>(buf[1]));
    }

    return hex;
}

// Prepares message for sending.
bytes prepSend(uint8_t type, const bytes& object) {
    std::vector<uint8_t> result;
    result.push_back(type);
    result.insert(result.end(), object.begin(), object.end());
    return bytes(result);
}

// Function to send data. Adapted from V1.0 thread.
int sendData(const bytes& message, const std::string& dest = destEid) {
    char* payload = const_cast<char*>(reinterpret_cast<const char*>(message.data()));
    size_t payloadLen = message.size();

    std::cout << "[INFO] Payload size: " << payloadLen << " bytes." << std::endl;

    // STart SDR transaction to allocate and write the payload data
    if (sdr_begin_xn(sdr) < 0) {
        std::cerr << "ERROR: Unable to begin SDR transaction for payload." << std::endl;
        return -1;
    }

    // Allocate space in SDR for the payload
    Object dataObj = sdr_malloc(sdr, payloadLen);
    if (dataObj == 0) {
        sdr_cancel_xn(sdr);
        std::cerr << payload << std::endl;
        std::cerr << payloadLen << std::endl;
        std::cerr << "ERROR: No space in SDR for payload allocation." << std::endl;
        return -1;
    }

    // Write the payload into the SDR allocated object
    sdr_write(sdr, dataObj, payload, payloadLen);
    if (sdr_end_xn(sdr) < 0) {
        std::cerr << "ERROR: SDR transaction failed, payload not stored." << std::endl;
        // Clean up and abort if we cannot store the payload
        sdr_begin_xn(sdr);
        sdr_free(sdr, dataObj);
        sdr_end_xn(sdr);
        return -1;
    }

    // Create a ZCO for the payload data in SDR.
    Object zco = ionCreateZco(ZcoSdrSource, dataObj, 0, payloadLen, 
                                0,          // coarsePriority
                                0,          // finePriority
                                ZcoOutbound, 
                                NULL);      // no ReqAttendant
    if (zco == -1) {
        std::cerr << "ERROR: ionCreateZco failed." << std::endl;
        // Free the SDR object if ZCO creation failed
        sdr_begin_xn(sdr);
        sdr_free(sdr, dataObj);
        sdr_end_xn(sdr);
        return -1;
    }
    if (zco == 0) {
        std::cerr << "WARNING: Insufficient ZCO space, bundle not sent. Retrying..." << std::endl;
        // Free the SDR object since no ZCO was created
        sdr_begin_xn(sdr);
        sdr_free(sdr, dataObj);
        sdr_end_xn(sdr);
        return -1;
    }

    // Send the bundle (no custody transfer, no status reports, standard priority)
    int sendResult = bp_send(
        sap_send,                   // BP send-only SAP handle
        (char*) dest.c_str(),       // Destination EID
        NULL,                       // Report-to EID (NULL => defaults to sourceEid)
        300,                        // Bundle lifespan (TTL) in seconds
        BP_STD_PRIORITY,            // Standard priority class of service
        NoCustodyRequested,         // No custody transfer requested
        0,                          // No status report requested
        false,                      // No application ack requested
        NULL,                       // No ancillary data (NULL for default Extended COS)
        zco,                        // Payload ZCO created above
        0                           // Bundle object handle (unused here)
    );
    if (sendResult < 0) {
        std::cerr << "ERROR: bp_send failed for bundle." << std::endl;
        // Destroy the ZCO since it wasn't sent
        if (sdr_begin_xn(sdr) >= 0) {
            zco_destroy(sdr, zco);
            sdr_end_xn(sdr);
        }
        return -1;
    } else {
        std::cout << "Sent bundle-> " << dest 
                    << " (" << payloadLen << " bytes)" << std::endl;
    }
    return 0;
}

// Writes key to SDR.
int addMLSKey (char* keyName, char* filePath) {
    // If we've already added a key, we must update vice add key.
    if (keyAdded) {
        if (sec_updateKey(keyName, filePath) != 1) {
            std::cerr << "Failed to update key." << std::endl;
            return -1;
        }
    } else {
        if (sec_addKey(keyName, filePath) != 1) {
            std::cerr << "Failed to add key." << std::endl;
            return -1;
        }
        keyAdded = true;
    }
    return 0;
}

// Using MLS API create and write key from group's exporter secret.
void writeKey() {
    bytes context = mls::tls::marshal(session->group_info().group_context);

    // Create key with name, context, and size.
    bytes key = session->do_export("BPSecKey", context, 16);
    // Write Key
    std::ofstream outfile("BPSecKey.hmk", std::ios::binary);
    if (outfile.is_open()) {
        outfile << key;
        outfile.close();
    } else {
        std::cerr << "Error: could not open BPSecKey.hmk\n";
    }
}

// Not used in v13
// For leader, update session, send commitMsg, and write new key.
void periodicUpdate() {
    while (running) {
        if (groupThreshold == thresholdCounter.size()) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            std::cout << "Generating update." << std::endl;

            auto [welcome, commit] = session->commit();
            mls::silence_unused(welcome);  // not needed for update
            session->handle(commit);
            auto message = prepSend(COMMIT, commit);

            std::cout << "Sending update to group." << std::endl;
            for (const auto& memberEid : activeGroupMembers) {
                std::cout << "[INFO] Sending update to " << memberEid << std::endl;
                sendData(message, memberEid);
            }

            writeKey();
            if (addMLSKey((char*)"BPSecKey", (char*)"BPSecKey.hmk") != 0) {
                std::cerr << "Error updating BPSec key." << std::endl;
            }
        }
    }
}

// Handles MLS messages
int handleMLS(char* buffer, size_t length, const char* senderEid) {
    auto wall_start = std::chrono::high_resolution_clock::now();
    struct rusage usage_start;
    getrusage(RUSAGE_SELF, &usage_start);

    std::ostringstream actionLog;
    uint8_t messageType = static_cast<uint8_t>(buffer[0]);

    std::vector<uint8_t> vec(reinterpret_cast<uint8_t*>(buffer + 1),
                             reinterpret_cast<uint8_t*>(buffer + length));
    bytes messageBytes(vec);

    std::cerr << "Received MLS message (type=" << static_cast<int>(messageType)
              << ", length=" << messageBytes.size() << ") from " << senderEid << std::endl;

    // Text log: what was received, who from, and size
    mls_log_recv(mls_type_name(messageType), messageBytes.size(), senderEid);

    // Like V9, gathers key packages
    if (messageType == KP && std::strcmp(sourceEid, "ipn:1.1") == 0) {

        // Queue key packages and joiner EIDs
        pendingKeyPackages.push_back(messageBytes);
        pendingJoiners.emplace_back(senderEid);
        std::cout << "[INFO] Collected KeyPackage for initial group from " << senderEid << std::endl;

        if (pendingKeyPackages.size() >= static_cast<size_t>(groupThreshold)) {
            std::cout << "[INFO] Forming initial group with " << pendingKeyPackages.size() << " members." << std::endl;

            std::vector<bytes> proposals;
            for (const auto& kp : pendingKeyPackages) {
                proposals.push_back(session->add(kp));
            }
            for (const auto& prop : proposals) {
                session->handle(prop);
            }

            // Create welcome + commit
            MlsOpStart s_create = mls_begin_op("create_welcome/create_commit");
            auto [welcome, commit] = session->commit();
            mls_log_text("OP create_welcome bytes=" + std::to_string(welcome.size()));
            mls_log_text("OP create_commit bytes="  + std::to_string(commit.size()));
            mls_write_metrics("create_welcome", s_create, sourceEid);
            mls_write_metrics("create_commit",  s_create, sourceEid);

            // Handle commit locally
            MlsOpStart s_handle = mls_begin_op("handle_commit");
            session->handle(commit);
            mls_log_text("OP handle_commit bytes=" + std::to_string(commit.size()));
            mls_write_metrics("handle_commit", s_handle, sourceEid);

            activeGroupMembers = pendingJoiners;
            std::cout << "Active group members: [";
            for (size_t i = 0; i < activeGroupMembers.size(); ++i) {
                std::cout << activeGroupMembers[i];
                if (i + 1 < activeGroupMembers.size()) std::cout << ", ";
            }
            std::cout << "]" << std::endl;

            auto welcomeMsg = prepSend(WELCOME, welcome);
            for (const auto& memberEid : pendingJoiners) {
                mls_log_send("WELCOME", welcomeMsg.size(), memberEid);
                sendData(welcomeMsg, memberEid);
            }

            actionLog << "Originator created session and initiated sending of welcome messages.";

            writeKey();
            addMLSKey((char*)"BPSecKey", (char*)"BPSecKey.hmk");

            pendingKeyPackages.clear();
            pendingJoiners.clear();
        }

    } else if (messageType == WELCOME) {
        if (!client_join.has_value()) {
            std::cerr << "[ERROR] No PendingJoin available\n";
            return -1;
        }

        // Complete join from welcome
        MlsOpStart s_join = mls_begin_op("complete_join_with_welcome");
        session = client_join->complete(messageBytes);
        mls_log_text("OP complete_join_with_welcome bytes=" + std::to_string(messageBytes.size()));
        mls_write_metrics("complete_join_with_welcome", s_join, sourceEid);

        actionLog << "Processed welcome message.";
        writeKey();
        addMLSKey((char*)"BPSecKey", (char*)"BPSecKey.hmk");

        // If node 2.1, create and handle an immediate commit
        if (std::strcmp(sourceEid, "ipn:2.1") == 0) {
            try {
                MlsOpStart s_create = mls_begin_op("create_welcome/create_commit");
                auto [welcome, commit] = session->commit();
                mls_log_text("OP create_commit bytes="  + std::to_string(commit.size()));
                mls_write_metrics("create_commit",  s_create, sourceEid);

                mls::silence_unused(welcome);

                MlsOpStart s_handle = mls_begin_op("handle_commit");
                session->handle(commit);
                mls_log_text("OP handle_commit bytes=" + std::to_string(commit.size()));
                mls_write_metrics("handle_commit", s_handle, sourceEid);

                writeKey();
                addMLSKey((char*)"BPSecKey", (char*)"BPSecKey.hmk");
                auto preppedCommit = prepSend(COMMIT, commit);
                mls_log_send("COMMIT", preppedCommit.size(), "ipn:1.1");
                sendData(preppedCommit, "ipn:1.1");
                actionLog << " Sent commit to ipn:1.1.";
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Failed to create/send update proposal: " << e.what() << std::endl;
                return -1;
            }
        }

    // This path not expected to be used in v13 as no proposals are sent over the wire.
    } else if (messageType == PROPOSAL) {
        std::cerr << "[ERROR] Proposal message detected." << std::endl;

        // Subordinate path
        if (std::strcmp(sourceEid, "ipn:1.1") != 0) {
            if (!session.has_value()) {
                return 0;
            }
            try {
                session->handle(messageBytes);
                std::cout << "Handled proposal." << std::endl;
                return 0;
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Subordinate failed to handle proposal: " << e.what() << std::endl;
                return -1;
            }
        }

        // Leader path
        try {
            pendingProposals.push_back(messageBytes);
            pendingProposers.emplace_back(senderEid);

            // Once we have one from each member
            if (pendingProposals.size() >= static_cast<size_t>(groupThreshold)) {

                for (size_t i = 0; i < pendingProposals.size(); ++i) {
                    const auto& propBytes = pendingProposals[i];
                    const auto& origin    = pendingProposers[i];

                    if (!activeGroupMembers.empty()) {
                        auto pkt = prepSend(PROPOSAL, propBytes);
                        for (const auto& m : activeGroupMembers) {
                            if (m == origin)                 continue;
                            if (m == std::string(sourceEid)) continue;
                            mls_log_send("PROPOSAL", pkt.size(), m);
                            sendData(pkt, m);
                        }
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                    }
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(1500));
                std::cout << "sent proposals to members" << std::endl;

                // Create commit from pending proposals
                MlsOpStart s_create = mls_begin_op("create_welcome/create_commit");
                auto [welcome, commit] = session->commit(pendingProposals);
                mls_log_text("OP create_commit bytes="  + std::to_string(commit.size()));
                mls_write_metrics("create_commit",  s_create, sourceEid);

                // Handle commit locally
                MlsOpStart s_handle = mls_begin_op("handle_commit");
                session->handle(commit);
                mls_log_text("OP handle_commit bytes=" + std::to_string(commit.size()));
                mls_write_metrics("handle_commit", s_handle, sourceEid);

                mls::silence_unused(welcome);

                // Send Commit to existing members (skip leader)
                if (!activeGroupMembers.empty()) {
                    auto commitMsg = prepSend(COMMIT, commit);
                    for (const auto& m : activeGroupMembers) {
                        if (m == std::string(sourceEid)) continue;
                        mls_log_send("COMMIT", commitMsg.size(), m);
                        sendData(commitMsg, m);
                    }
                }

                actionLog << "Leader: gossiped proposals, committed, sent commit.";
                writeKey();
                addMLSKey((char*)"BPSecKey", (char*)"BPSecKey.hmk");

                pendingProposals.clear();
                pendingProposers.clear();
            }

        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Proposal handling failed: " << e.what() << std::endl;
            return -1;
        }

    // If commit, apply it
    } else if (messageType == COMMIT) {
        commitCounter += 2;

        // Always handle the commit
        try {
            MlsOpStart s_handle = mls_begin_op("handle_commit");
            session->handle(messageBytes);
            mls_log_text("OP handle_commit bytes=" + std::to_string(messageBytes.size()));
            mls_write_metrics("handle_commit", s_handle, sourceEid);
            actionLog << "Processed commit message.";

            writeKey();
            addMLSKey((char*)"BPSecKey", (char*)"BPSecKey.hmk");
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to handle commit: " << e.what() << std::endl;
            return -1;
        }

        // Leader rebroadcasts commit (except back to sender)
        if (std::strcmp(sourceEid, "ipn:1.1") == 0) {
            if (!activeGroupMembers.empty()) {
                auto commitMsg = prepSend(COMMIT, messageBytes);
                for (const auto& m : activeGroupMembers) {
                    if (m == std::string(senderEid)) continue;
                    mls_log_send("COMMIT", commitMsg.size(), m);
                    sendData(commitMsg, m);
                }
            }

        // If this node's number matches commitCounter, create and send a new commit
        } else if (std::strcmp(sourceEid, "ipn:1.1") != 0) {
            int nodeNum = extract_ipn_node(sourceEid);
            std::cout << "Is nodeNum " << nodeNum << " is commitCounter " << commitCounter << std::endl;
            if (nodeNum == commitCounter) {
                try {
                    std::this_thread::sleep_for(std::chrono::milliseconds(750));
                    MlsOpStart s_create = mls_begin_op("create_welcome/create_commit");
                    auto [welcome, commit] = session->commit();
                    mls_log_text("OP create_commit bytes="  + std::to_string(commit.size()));
                    mls_write_metrics("create_commit",  s_create, sourceEid);

                    mls::silence_unused(welcome);

                    MlsOpStart s_handle2 = mls_begin_op("handle_commit");
                    session->handle(commit);
                    mls_log_text("OP handle_commit bytes=" + std::to_string(commit.size()));
                    mls_write_metrics("handle_commit", s_handle2, sourceEid);

                    auto commitMsg = prepSend(COMMIT, commit);
                    mls_log_send("COMMIT", commitMsg.size(), "ipn:1.1");
                    sendData(commitMsg, "ipn:1.1");
                    actionLog << "Created and committed update. Send commit to leader.";

                    writeKey();
                    addMLSKey((char*)"BPSecKey", (char*)"BPSecKey.hmk");
                } catch (const std::exception& e) {
                    std::cerr << "[ERROR] Failed to handle commit: " << e.what() << std::endl;
                    return -1;
                }
            }
        }
    }

    // Build text log
    auto wall_end = std::chrono::high_resolution_clock::now();
    struct rusage usage_end;
    getrusage(RUSAGE_SELF, &usage_end);

    std::chrono::duration<double, std::milli> wall_duration = wall_end - wall_start;
    double user_cpu_time = (usage_end.ru_utime.tv_sec - usage_start.ru_utime.tv_sec) * 1000.0 +
                           (usage_end.ru_utime.tv_usec - usage_start.ru_utime.tv_usec) / 1000.0;
    double sys_cpu_time  = (usage_end.ru_stime.tv_sec - usage_start.ru_stime.tv_sec) * 1000.0 +
                           (usage_end.ru_stime.tv_usec - usage_start.ru_stime.tv_usec) / 1000.0;

    double percent_cpu = 0.0;
    if (wall_duration.count() > 0.0) {
        percent_cpu = ((user_cpu_time + sys_cpu_time) / wall_duration.count()) * 100.0;
    }

    std::ofstream logFile("mlslog.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << currentTimestamp() << "] "
                << "handleMLS took " << wall_duration.count() << " ms. "
                << "CPU %: " << percent_cpu << " "
                << "Action: " << actionLog.str() << "\n";
        logFile.close();
    }

    return 0;
}

// Thread function for receiving incoming bundles
void* receiveBundles(void* arg) {
    (void)arg;
    BpDelivery dlv;
    memset(&dlv, 0, sizeof(dlv));    

    while (running) {
        // Wait for the next bundle
        int recvResult = bp_receive(sap_receive, &dlv, BP_BLOCKING);
        if (recvResult < 0) {
            std::cerr << "ERROR: bp_receive failed." << std::endl;
            break;
        }
        if (dlv.result == BpPayloadPresent) {
            // A payload-bearing bundle was received
            Object incomingZco = dlv.adu;              // ZCO containing the payload
            vast dataLen = zco_length(sdr, incomingZco);
            if (dataLen < 0) {
                std::cerr << "ERROR: Cannot determine payload length." << std::endl;
            } else {
                // Retrieve the payload data from the ZCO
                char *buffer = new char[dataLen];
                if (!buffer) {
                    std::cerr << "ERROR: Out of memory for payload buffer." << std::endl;
                } else {
                    sdr_begin_xn(sdr);
                    ZcoReader reader;
                    zco_start_receiving(incomingZco, &reader);
                    int bytesRead = zco_receive_source(sdr, &reader, dataLen, buffer);
                    sdr_end_xn(sdr);
                    if (bytesRead < 0) {
                        std::cerr << "ERROR: zco_receive failed." << std::endl;
                    } else {
                        handleMLS(buffer, bytesRead, dlv.bundleSourceEid ? dlv.bundleSourceEid : "UNKNOWN");
                    }
                    delete [] buffer;
                }
            }
            // Release the delivery 
            bp_release_delivery(&dlv, 1);
        } else if (dlv.result == BpReceptionInterrupted) {
            // bp_receive was interrupted
            std::cout << "Reception interrupted, closing receive thread." << std::endl;
            dlv.result = BpPayloadPresent;
            bp_release_delivery(&dlv, 0);
            break;
        } else if (dlv.result == BpEndpointStopped) {
            // The endpoint is closing 
            std::cout << "Endpoint stopped, receive thread exiting." << std::endl;
            bp_release_delivery(&dlv, 0);
            break;
        } else {
            // Other outcomes just release
            bp_release_delivery(&dlv, 0);
            std::cerr << "Else case in receive thread." << std::endl;
        }
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        std::cerr << "Arguments:\n"
                << "  Originator: " << argv[0] << " <group_size> <source_eid>\n"
                << "  Joiner:     " << argv[0] << " <group_size> <source_eid> <dest_eid>\n";
        return 1;
    }

    groupThreshold = std::stoi(argv[1]);
    sourceEid = argv[2];

    // Only set destEid for joiners
    if (argc == 4) {
        destEid = argv[3];
    }

    std::cout << "[INFO] Starting node with EID: " << sourceEid << std::endl;
    if (destEid != nullptr) {
        std::cout << "[INFO] Destination EID: " << destEid << std::endl;
    }

    // Attach to the BP agent
    if (bp_attach() < 0) {
        std::cerr << "[ERROR] Cannot attach to BP daemon. Is ION running?" << std::endl;
        return 1;
    }
    // Open the local source endpoint for receiving bundles
    if (bp_open((char*) sourceEid, &sap_receive) < 0) {
        std::cerr << "ERROR: Cannot open source endpoint " << sourceEid << std::endl;
        bp_detach();
        return 1;
    }
    // Open a send-only SAP for the same endpoint (detain=0 for no bundle retention)
    if (bp_open_source((char*) sourceEid, &sap_send, 0) < 0) {
        std::cerr << "ERROR: Cannot open source endpoint for sending " << sourceEid << std::endl;
        bp_close(sap_receive);
        bp_detach();
        return 1;
    }

    // Get the SDR handle for bundle payload operations
    sdr = bp_get_sdr();

    // Set up SIGINT handler for graceful shutdown
    std::signal(SIGINT, handle_sigint);

    // Attach to ION secDB.
    if (secAttach() != 0) {
        std::cerr << "Error with attaching to security database." << std::endl;
    }

    // Enable BPSec Policies
    //runScriptInBackground("enable_rule.sh");    // commented out to prevent break

    // Build client name.
    std::cout << "Is sourceEid " << sourceEid << std::endl;
    auto clientName = from_ascii((char*) sourceEid);

    // Establish client.
    client.emplace(
        SUITE,
        mls::SignaturePrivateKey::generate(SUITE),
        mls::Credential::basic(clientName)
    );

    //Originator behavior.
    if (std::strcmp(sourceEid, "ipn:1.1") == 0) {
        // Using globally declared mls:Session variable.
        session = client->begin_session(from_ascii("IONMLS"));
    
        pthread_t updateThread;
        pthread_create(&updateThread, NULL, [](void*) -> void* {
            periodicUpdate();
            return nullptr;
        }, NULL);
    }

    // Non originator behavior.
    if (std::strcmp(sourceEid, "ipn:1.1") != 0) {
        client_join = client->start_join();
        auto kp = client_join->key_package();
        auto message = prepSend(KP, kp);
        sendData(message);
    }

    // Launch receiver thread
    pthread_t recvThread;
    if (pthread_create(&recvThread, NULL, receiveBundles, NULL) != 0) {
        std::cerr << "ERROR: Failed to start receive thread." << std::endl;
        bp_close(sap_send);
        bp_close(sap_receive);
        bp_detach();
        return 1;
    }

    // Wait for thread to finish
    pthread_join(recvThread, NULL);

    // Close endpoints and detach from ION
    bp_close(sap_send);
    bp_close(sap_receive);
    bp_detach();
    std::cout << "Program terminated cleanly." << std::endl;
    return 0;
}
