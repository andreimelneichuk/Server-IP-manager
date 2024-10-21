#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <mutex>
#include <regex>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

std::ofstream log_file;
std::mutex log_mutex;

void log(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    log_file << "[INFO] " << message << std::endl;
    std::cout << "[INFO] " << message << std::endl;
}

void log_error(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    log_file << "[ERROR] " << message << std::endl;
    std::cerr << "[ERROR] " << message << std::endl;
}

void init_log() {
    log_file.open("server_log.txt", std::ios_base::app);
    if (!log_file.is_open()) {
        throw std::runtime_error("Failed to open log file");
    }
    log("Log file initialized.");
}

void close_log() {
    log("Closing log file.");
    if (log_file.is_open()) {
        log_file.close();
    }
}

std::string get_ip_address(const std::string& interface) {
    log("Attempting to get IP address for interface: " + interface);
    std::string command = "ip addr show dev " + interface + " | grep 'inet '";
    char buffer[128];
    std::string result;
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        log_error("Error getting IP address");
        return "Error";
    }
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    pclose(pipe);
    log("IP address obtained: " + result);
    return result;
}

int mask_to_prefix(const std::string& mask) {
    if (mask == "255.255.255.0") return 24;
    if (mask == "255.255.0.0") return 16;
    if (mask == "255.0.0.0") return 8;
    // Добавьте другие маски, если необходимо
    return -1;  // Ошибка, если маска неизвестна
}

void set_ip_address(const std::string& interface, const std::string& ip, const std::string& mask) {
    int prefix = mask_to_prefix(mask);
    if (prefix == -1) {
        log_error("Invalid subnet mask: " + mask);
        return;
    }

    log("Attempting to set IP address: " + ip + " with mask: " + mask + " on interface: " + interface);
    std::string command = "ip addr add " + ip + "/" + std::to_string(prefix) + " dev " + interface;
    int result = system(command.c_str());
    if (result == 0) {
        log("IP address and mask successfully set.");
    } else {
        log_error("Failed to set IP address and mask.");
    }
}


void handle_telnet_session(tcp::socket& socket) {
    log("Starting Telnet session.");
    try {
        asio::streambuf buf;
        asio::read_until(socket, buf, "\n");
        std::istream input(&buf);
        std::string command;
        std::getline(input, command);
        log("Telnet command received: " + command+"");

        if (command.substr(0,6) == "get_ip") {
            std::string ip_info = get_ip_address("enp0s1");
            asio::write(socket, asio::buffer(ip_info + "\n"));
            log("Sent IP information to Telnet client.");
        } else if (command.substr(0, 7) == "set_ip ") {
            std::istringstream iss(command.substr(7));
            std::string ip, mask;
            iss >> ip >> mask;

            if (iss.fail() || ip.empty() || mask.empty()) {
                log_error("Invalid set_ip command format.");
                asio::write(socket, asio::buffer("Invalid set_ip command format\n"));
            } else {
                set_ip_address("enp0s1", ip, mask);
                asio::write(socket, asio::buffer("IP and mask updated successfully\n"));
                log("IP and mask updated via Telnet session.");
            }
        } else {
            asio::write(socket, asio::buffer("Invalid command\n"));
            log("Invalid Telnet command received.");
        }
    } catch (const std::exception& e) {
        log_error("Error handling Telnet session: " + std::string(e.what()));
    }
    log("Telnet session ended.");
}

void run_telnet_server() {
    log("Initializing Telnet server on port 2323.");
    try {
        asio::io_context io_context;
        tcp::acceptor telnet_acceptor(io_context, tcp::endpoint(tcp::v4(), 2323));

        while (true) {
            log("Waiting for Telnet connection...");
            tcp::socket socket(io_context);
            telnet_acceptor.accept(socket);
            log("Telnet connection accepted.");
            handle_telnet_session(socket);
        }
    } catch (const std::exception& e) {
        log_error("Error in Telnet server: " + std::string(e.what()));
    }
}

int main() {
    try {
        init_log();
        log("Starting Telnet server...");

        run_telnet_server();

    } catch (const std::exception& e) {
        log_error("Server encountered an error: " + std::string(e.what()));
    }

    close_log();
    return 0;
}
