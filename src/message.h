#include <string>
#include <memory>
#include <tuple>
#include <vector>
#include <stdint.h>

enum message_type {error_msg, process_start_msg, process_info_msg, process_end_msg};

void copy_to_buffer(std::byte *buffer, uint32_t *offset, uint32_t buffer_size, void *data, uint32_t data_size)
{
    memcpy_s(buffer + *offset, buffer_size - *offset, data, data_size);
    *offset += data_size;
}

void copy_uint32_to_buffer(std::byte *buffer, uint32_t *offset, uint32_t buffer_size, uint32_t data)
{
    copy_to_buffer(buffer, offset, buffer_size, &data, sizeof(data));
}

void copy_string_to_buffer(std::byte *buffer, uint32_t *offset, uint32_t buffer_size, std::string &data)
{
    uint32_t size = data.size();
    copy_uint32_to_buffer(buffer, offset, buffer_size, size);
    copy_to_buffer(buffer, offset, buffer_size, &data, size);  // TODO: this isn't right
}

std::tuple<std::unique_ptr<std::byte[]>, uint32_t, uint32_t> create_buffer(message_type type, uint32_t buffer_size)
{
    uint32_t total_size = sizeof(type) + sizeof(uint32_t) + buffer_size;

    uint32_t offset = 0;
    auto buffer = std::make_unique<std::byte[]> (total_size);

    copy_uint32_to_buffer(buffer.get(), &offset, total_size, type);
    copy_uint32_to_buffer(buffer.get(), &offset, total_size, buffer_size);

    return std::make_tuple(std::move(buffer), total_size, offset);
}

namespace message
{
    class error
    {
        public:
            uint32_t error_code;
            std::string message;

            std::unique_ptr<std::byte[]> serialize()
            {
                uint32_t message_size = message.size();
                auto [buffer, buffer_size, offset] = create_buffer(error_msg, sizeof(error_code) + sizeof(uint32_t) + message_size);

                copy_uint32_to_buffer(buffer.get(), &offset, buffer_size, error_code);
                copy_string_to_buffer(buffer.get(), &offset, buffer_size, message);

                return std::move(buffer);
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