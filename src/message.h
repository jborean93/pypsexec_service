#ifndef MESSAGE_H
#define MESSAGE_H
#include <string>
#include <tuple>
#include <vector>
#include <stdint.h>

enum message_type {error_msg, process_start_msg, process_info_msg, process_end_msg};

void copy_to_buffer(std::vector<std::byte> &buffer, uint32_t *offset, const void *data, uint32_t size)
{
    memcpy_s(&buffer[*offset], buffer.capacity() - *offset, data, size);
    *offset += size;
}

void copy_uint32_to_buffer(std::vector<std::byte> &buffer, uint32_t *offset, uint32_t data)
{
    copy_to_buffer(buffer, offset, &data, sizeof(data));
}

void copy_string_to_buffer(std::vector<std::byte> &buffer, uint32_t *offset, const std::string &data)
{
    uint32_t size = data.size();
    copy_uint32_to_buffer(buffer, offset, size);
    copy_to_buffer(buffer, offset, &data[0], size);
}

std::tuple<std::vector<std::byte>, uint32_t> create_buffer(message_type type, uint32_t buffer_size)
{
    uint32_t total_size = sizeof(uint32_t) + sizeof(type) + sizeof(uint32_t) + buffer_size;

    std::vector<std::byte> buffer (total_size);
    uint32_t offset = 0;

    copy_uint32_to_buffer(buffer, &offset, total_size - sizeof(uint32_t));  // TODO: move this encryption method.
    copy_uint32_to_buffer(buffer, &offset, type);
    copy_uint32_to_buffer(buffer, &offset, buffer_size);

    return std::make_tuple (buffer, offset);
}

namespace message
{
    class error
    {
        public:
            uint32_t error_code;
            std::string message;

            error(uint32_t error_code, const std::string &message) : error_code(error_code), message(message) {}

            std::vector<std::byte> serialize()
            {
                uint32_t message_size = sizeof(error_code) + sizeof(uint32_t) + message.size();
                auto [buffer, offset] = create_buffer(error_msg, message_size);

                copy_uint32_to_buffer(buffer, &offset, error_code);
                copy_string_to_buffer(buffer, &offset, message);

                return buffer;
            }
    };

    class process_start
    {
        public:
            // LsaLogonUser() and other token manipulation options
            bool user_is_sid;
            std::string username;
            std::string password;
            uint32_t logon_type;
            uint32_t session_id;
            bool load_profile;

            // CreateProcess()
            std::string application_name;
            std::string command_line;
            uint32_t creation_flags;  // Also includes dwCreationFlags
            std::string current_directory;
            std::string desktop;  // STARTUPINFO
            std::vector<uint32_t> processors;  // STARTUPINFOEX - lpAttributeList
            bool asynchronous;
            uint32_t timeout_seconds;
            bool wow64_fs_redirection;
    };

    class process_info
    {
        public:
            uint32_t task_id;
            uint32_t process_id;
            uint32_t thread_id;
    };

    class process_end
    {
        public:
            uint32_t return_code;
    };
}
#endif // MESSAGE_H