#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <vector>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ws = beast::websocket;
using tcp = asio::ip::tcp;
using json = nlohmann::json;



std::ofstream log_file;
std::vector<std::shared_ptr<ws::stream<tcp::socket>>> clients;

// Логирование
void log(const std::string& message) {
    log_file << "[INFO] " << message << std::endl;
    std::cout << "[INFO] " << message << std::endl;
}

void log_error(const std::string& message) {
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

// Установка IP-адреса
void set_ip_address(const std::string& interface, const std::string& ip, const std::string& mask) {
    log("Attempting to set IP address: " + ip + " with mask: " + mask + " on interface: " + interface);
    std::string command = "ip addr add " + ip + "/" + mask + " dev " + interface;
    int result = system(command.c_str());
    if (result == 0) {
        log("IP address and mask successfully set.");

        // Отправка сообщения всем клиентам WebSocket
        json msg;
        msg["ip"] = ip;
        msg["mask"] = mask;
        msg["status"] = "updated";

        log("Sending messages for subscribers");

        for (const auto& client : clients) {
            std::string message = msg.dump();
            client->async_write(asio::buffer(message), [](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    std::cerr << "Error sending message: " << ec.message() << std::endl;
                }
            });
        }
        log("Messages send");
    } else {
        log_error("Failed to set IP address and mask.");
    }
}

// Проверка авторизации
bool authenticate(const http::request<http::string_body>& req) {
    auto auth_header = req.find(http::field::authorization);
    if (auth_header != req.end()) {
        std::string auth_value = auth_header->value().to_string();
        return (auth_value == "Bearer 1");  // Замените на ваш токен
    }
    return false;
}

// Обработка HTTP запросов
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
    // Асинхронно принимаем WebSocket соединение с использованием буфера HTTP-запроса
    ws->async_accept(*req, [ws](boost::system::error_code ec) {
        if (ec) {
            log_error("Error accepting WebSocket connection: " + ec.message());
        } else {
            log("WebSocket connection accepted.");

            // Отправляем приветственное сообщение клиенту
            json welcome_msg;
            welcome_msg["status"] = "connected";
            welcome_msg["message"] = "You are now subscribed to updates.";
            std::string message = welcome_msg.dump();

            ws->async_write(asio::buffer(message), [ws](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    log_error("Error sending welcome message: " + ec.message());
                } else {
                    log("Welcome message sent to client.");
                }
            });

            clients.push_back(std::move(ws));

            // Создаем буфер для чтения сообщений
            auto buffer = std::make_shared<beast::flat_buffer>();

            // Начинаем асинхронное чтение сообщений от клиента
            ws->async_read(*buffer, [ws, buffer](boost::system::error_code ec, std::size_t /*bytes_transferred*/) {
                if (!ec) {
                    // Обработка полученного сообщения
                    std::string received_message = beast::buffers_to_string(buffer->data());
                    log("Received message from client: " + received_message);
                    buffer->consume(buffer->size());  // Очищаем буфер

                    // Здесь можно обрабатывать сообщения от клиента
                    
                    // После обработки, снова начинаем асинхронное чтение
                    handle_websocket_connection(ws, nullptr); // Вызовем функцию снова для чтения следующего сообщения
                } else {
                    log_error("WebSocket read error: " + ec.message());
                }
            });
        }
    });
}


// Функция для асинхронного принятия новых соединений
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

// Основная функция
int main() {
    try {
        init_log(); // Инициализация логирования
        asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8001));
        log("Server started on port 8001.");

        do_accept(acceptor, io_context); // Начинаем принимать соединения
        io_context.run(); // Запускаем цикл обработки событий
    } catch (const std::exception& e) {
        log_error("Error in main: " + std::string(e.what()));
    }
         close_log(); // Закрываем лог файл
   
    return 0;
}
