#include <iostream>
#include <boost/asio.hpp>
#include <string>
#include <fstream>

using namespace boost::asio;
using boost::asio::local::stream_protocol;

// Открытие файла для логирования
std::ofstream log_file("client_log.txt", std::ios_base::app);

// Функция для логирования
void log(const std::string& message) {
    log_file << "[INFO] " << message << std::endl;
    std::cout << "[INFO] " << message << std::endl;
}

// Функция для логирования ошибок
void log_error(const std::string& message) {
    log_file << "[ERROR] " << message << std::endl;
    std::cerr << "[ERROR] " << message << std::endl;
}

void send_request(const std::string& command) {
    try {
        // Логирование отправки команды
        log("Sending request: " + command);

        // Подключение к UNIX-сокету
        io_service io_service;
        stream_protocol::socket socket(io_service);
        socket.connect(stream_protocol::endpoint("/tmp/unix_socket"));

        // Отправка команды серверу
        write(socket, buffer(command + "\n"));

        // Получение ответа от сервера
        boost::asio::streambuf response;
        read_until(socket, response, "\n");

        std::istream is(&response);
        std::string reply;
        std::getline(is, reply);

        // Логирование ответа сервера
        log("Server reply: " + reply);

        // Вывод ответа
        std::cout << "Server reply: " << reply << std::endl;
    } catch (const std::exception& e) {
        // Логирование ошибки
        log_error("Error: " + std::string(e.what()));
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        log_error("Incorrect usage");
        std::cerr << "Usage: " << argv[0] << " <command> [args]" << std::endl;
        std::cerr << "Commands:" << std::endl;
        std::cerr << "  get_ip" << std::endl;
        std::cerr << "  set_ip <IP> <MASK>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "get_ip") {
        log("Executing 'get_ip' command");
        send_request("get_ip");
    } else if (command == "set_ip") {
        if (argc != 4) {
            log_error("Incorrect usage of 'set_ip' command");
            std::cerr << "Usage: " << argv[0] << " set_ip <IP> <MASK>" << std::endl;
            return 1;
        }
        std::string ip = argv[2];
        std::string mask = argv[3];
        log("Executing 'set_ip' command with IP: " + ip + ", MASK: " + mask);
        send_request("set_ip " + ip + " " + mask);
    } else {
        log_error("Unknown command: " + command);
        std::cerr << "Unknown command: " << command << std::endl;
    }

    return 0;
}