#include <iostream>
#include <boost/asio.hpp>
#include <string>
#include <fstream>
#include <array>
#include <cstdlib>



using namespace boost::asio;
using boost::asio::local::stream_protocol;

std::ofstream log_file("server_log.txt", std::ios_base::app);

// Логирование сообщений
void log(const std::string& message) {
    log_file << "[INFO] " << message << std::endl;
    std::cout << "[INFO] " << message << std::endl;
}

// Логирование ошибок
void log_error(const std::string& message) {
    log_file << "[ERROR] " << message << std::endl;
    std::cerr << "[ERROR] " << message << std::endl;
}

// Получение IP-адреса интерфейса
std::string get_ip_address(const std::string& interface) {
    std::string command = "ip -4 addr show dev " + interface + " | grep 'inet '";
    std::array<char, 128> buffer;
    std::string result;
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        log_error("Failed to get IP address.");
        return "Error";
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    pclose(pipe);
    return result.empty() ? "IP not found" : result;
}

// Установка IP-адреса и маски интерфейса
std::string set_ip_address(const std::string& interface, const std::string& ip, const std::string& mask) {
    std::string command = "ip addr add " + ip + "/" + mask + " dev " + interface;
    int result = system(command.c_str());
    if (result == 0) {
        return "IP and mask set successfully";
    } else {
        return "Failed to set IP and mask";
    }
}

// Обработка команд от клиента
std::string process_command(const std::string& command) {
    if (command == "get_ip") {
        return get_ip_address("enp0s1"); // Укажите свой интерфейс
    } else if (command.find("set_ip") == 0) {
        std::istringstream iss(command);
        std::string cmd, ip, mask;
        iss >> cmd >> ip >> mask;
        if (!ip.empty() && !mask.empty()) {
            return set_ip_address("enp0s1", ip, mask);
        } else {
            return "Invalid IP or mask";
        }
    }
    return "Unknown command";
}

// Основная функция для обработки запросов через UNIX-сокет
void handle_client(stream_protocol::socket socket) {
    try {
        boost::asio::streambuf buffer;
        read_until(socket, buffer, "\n");

        std::istream is(&buffer);
        std::string command;
        std::getline(is, command);

        log("Received command: " + command);

        // Обработка команды
        std::string response = process_command(command);

        // Логирование результата
        log("Response: " + response);

        // Отправка ответа клиенту
        write(socket, boost::asio::buffer(response + "\n"));
    } catch (std::exception& e) {
        log_error("Error handling client: " + std::string(e.what()));
    }
}

int main() {
    try {
        log("Starting server...");

        io_service io_service;
        stream_protocol::endpoint endpoint("/tmp/unix_socket");

        // Удаляем старый сокет, если он существует
        std::remove("/tmp/unix_socket");

        stream_protocol::acceptor acceptor(io_service, endpoint);
        log("Server is listening on UNIX socket: /tmp/unix_socket");

        while (true) {
            stream_protocol::socket socket(io_service);
            acceptor.accept(socket);
            log("Client connected");
            handle_client(std::move(socket)); // Обработка клиента
        }
    } catch (std::exception& e) {
        log_error("Server error: " + std::string(e.what()));
    }

    return 0;
}