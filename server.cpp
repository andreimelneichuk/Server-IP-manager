#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <vector>
#include <mutex>
#include <regex>
#include <boost/asio/local/stream_protocol.hpp>
#include <string>
#include <array>
#include <cstdlib>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ws = beast::websocket;
using tcp = asio::ip::tcp;
using json = nlohmann::json;
using namespace boost::asio;
using boost::asio::local::stream_protocol;

std::ofstream log_file;
std::mutex log_mutex;
std::vector<std::shared_ptr<ws::stream<tcp::socket>>> clients;

// Логирование
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

// Получение IP-адреса
std::string get_ip_address(const std::string& interface) {
    log("Attempting to get IP address for interface: " + interface);
    std::string command = "ip -4 addr show dev " + interface + " | grep 'inet '";
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
    return -1;
}

// Установка IP-адреса
void set_ip_address(const std::string& interface, const std::string& ip, const std::string& mask) {
    int prefix = 0;
    if (mask.find(".")!= std::string::npos) {
        prefix = mask_to_prefix(mask);
    }
    else{
        prefix = stoi(mask);
    }

    if (prefix == -1) {
        log_error("Invalid subnet mask: " + mask);
        return;
    }

    log("Attempting to set IP address: " + ip + " with mask: " + mask + " on interface: " + interface);
    std::string command = "ip addr add " + ip + "/" + std::to_string(prefix) + " dev " + interface;
    int result = system(command.c_str());
    if (result == 0) {
        log("IP address and mask successfully set.");

        // Отправка сообщения всем клиентам WebSocket
        json msg;
        msg["ip"] = ip;
        msg["mask"] = mask;
        msg["status"] = "updated";

        for (const auto& client : clients) {
            std::string message = msg.dump();
            client->async_write(asio::buffer(message), [](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    log_error("Error sending message: " + ec.message());
                }
            });
        }
    } else {
        log_error("Failed to set IP address and mask.");
    }
}

// Проверка авторизации для HTTP-запросов
bool authenticate(const http::request<http::string_body>& req) {
    auto auth_header = req.find(http::field::authorization);
    if (auth_header != req.end()) {
        std::string auth_value = auth_header->value().to_string();
        return (auth_value == "Bearer 1");  // Замените на ваш токен
    }
    return false;
}



// Обработка Telnet-сессии
void handle_telnet_session(tcp::socket& socket) {
    log("Starting Telnet session.");
    try {
        asio::streambuf buf;
        asio::read_until(socket, buf, "\n");
        std::istream input(&buf);
        std::string command;
        std::getline(input, command);
        log("Telnet command received: " + command);

        if (command.substr(0, 6) == "get_ip") {
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

// Запуск Telnet-сервера
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

std::string process_command(const std::string& command) {
    if (command == "get_ip") {
        return get_ip_address("enp0s1"); // Укажите свой интерфейс
    } else if (command.find("set_ip") == 0) {
        std::istringstream iss(command);
        std::string cmd, ip, mask;
        iss >> cmd >> ip >> mask;
        if (!ip.empty() && !mask.empty()) {
            set_ip_address("enp0s1", ip, mask);
            return "IP address and mask successfully set";
        } else {
            return "Invalid IP or mask";
        }
    }
}

// Обработка UNIX сокета
void handle_unix_socket(stream_protocol::socket socket) {
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

// Обработка HTTP и WebSocket соединений
void handle_http_request(beast::tcp_stream& stream, http::request<http::string_body>& req) {
    log("Received HTTP request. Method: " + std::string(req.method_string()) + ", Target: " + std::string(req.target()));
    try {
        if (!authenticate(req)) {
            http::response<http::string_body> res{http::status::unauthorized, req.version()};
            res.body() = "Unauthorized";
            res.prepare_payload();
            http::write(stream, res);
            log("Unauthorized access attempt.");
            return;
        }

        if (req.method() == http::verb::get) {
            std::string ip_info = get_ip_address("enp0s1");
            http::response<http::string_body> res{http::status::ok, req.version()};
            res.set(http::field::server, "IP Server");
            res.body() = ip_info;
            res.prepare_payload();
            http::write(stream, res);
            log("HTTP GET request processed successfully.");
        } else if (req.method() == http::verb::post) {
            auto json_body = json::parse(req.body());
            std::string ip = json_body["ip"];
            std::string mask = json_body["mask"];
            log("Received data for IP: " + ip + ", Mask: " + mask);
            set_ip_address("enp0s1", ip, mask);
            http::response<http::string_body> res{http::status::ok, req.version()};
            res.set(http::field::server, "IP Server");
            res.body() = "IP and mask updated successfully.";
            res.prepare_payload();
            http::write(stream, res);
            log("HTTP POST request processed successfully.");
        }
    } catch (const std::exception& e) {
        log_error("Error handling HTTP request: " + std::string(e.what()));
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.body() = "Invalid JSON data.";
        res.prepare_payload();
        http::write(stream, res);
        log("HTTP request failed due to invalid JSON data.");
    }
}

// Обработка WebSocket соединений
void handle_websocket_connection(std::shared_ptr<ws::stream<tcp::socket>> ws, std::shared_ptr<http::request<http::string_body>> req) {
    ws->async_accept(*req, [ws](boost::system::error_code ec) {
        if (!ec) {
            log("WebSocket connection accepted.");
            json welcome_msg = {{"status", "connected"}, {"message", "Welcome to IP Manager"}};
            ws->async_write(asio::buffer(welcome_msg.dump()), [](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    log_error("WebSocket write error: " + ec.message());
                }
            });
            clients.push_back(ws);  // Добавляем клиента в список клиентов
        } else {
            log_error("WebSocket connection error: " + ec.message());
        }
    });
}

void do_accept(tcp::acceptor& acceptor, asio::io_context& io_context) {
    acceptor.async_accept([&acceptor, &io_context](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
            log("Connection accepted.");  // Запись в лог успешного принятия соединения
            
            // Создаем общий поток для обработки HTTP и WebSocket соединений
            auto stream = std::make_shared<beast::tcp_stream>(std::move(socket));
            // Создаем буфер для хранения данных
            auto buffer = std::make_shared<beast::flat_buffer>();
            // Создаем указатель на запрос HTTP
            auto req = std::make_shared<http::request<http::string_body>>();

            // Асинхронное чтение HTTP-запроса
            http::async_read(*stream, *buffer, *req, [stream, buffer, req](boost::system::error_code ec, std::size_t) {
                if (!ec) { 
                    if (req->find(http::field::upgrade) != req->end() && req->at(http::field::upgrade) == "websocket") {
                        log("WebSocket connection requested.");
                        // Обрабатываем WebSocket соединение
                        auto ws = std::make_shared<ws::stream<tcp::socket>>(std::move(stream->release_socket()));
                        // Переносим вызов accept в handle_websocket_connection
                        handle_websocket_connection(ws, req);
                    } else {
                        log("HTTP connection detected.");
                        handle_http_request(*stream, *req);
                    }
                } else {
                    log_error("Error reading HTTP request: " + ec.message());
                }
            });
        } else {
            log_error("Error accepting connection: " + ec.message());
        }
        do_accept(acceptor, io_context); // Принимаем следующее соединение
    });
}


// Запуск HTTP/WebSocket сервера
void run_http_ws_server() {
    log("Starting HTTP/WebSocket server on port 8001.");
    try{
        asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8001));
        log("HTTP/Websocket server started on port 8001.");
        do_accept(acceptor, io_context); // Начинаем принимать соединения
        io_context.run(); // Запускаем цикл обработки событий
    } catch (const std::exception& e) {
        log_error("Error in HTTP Server: " + std::string(e.what()));
    }
}

void run_unix_server(){
    try {
        log("Starting unix server...");

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
            handle_unix_socket(std::move(socket)); // Обработка клиента
        }
    } catch (std::exception& e) {
        log_error("Server error: " + std::string(e.what()));
    }

}

int main() {
    try {
        init_log();
        log("Server started.");

        // Запуск Telnet и HTTP/WebSocket серверов в отдельных потоках
        std::thread telnet_server_thread(run_telnet_server);
        std::thread http_ws_server_thread(run_http_ws_server);
        std::thread unix_server_thread(run_unix_server);

        telnet_server_thread.join();
        http_ws_server_thread.join();
        unix_server_thread.join();
    } catch (const std::exception& e) {
        log_error("Fatal error: " + std::string(e.what()));
    }

    close_log();
    return 0;
}