#ifndef TOKEN_H
#define TOKEN_H
#include <optional>
#include <vector> 
#include "win32.h"

namespace token_helper
{
    struct privilege_state
    {
        std::string privilege;
        uint32_t attribute;
    };

    void impersonate_system();

    wil::unique_handle logon_user(const std::string &username, std::optional<std::string> password = std::nullopt,
        uint32_t logon_type = 0, PTOKEN_GROUPS groups = nullptr);

    std::vector<privilege_state> set_privileges(const std::vector<privilege_state> &privileges);

    void set_session_id(HANDLE token, uint32_t session_id);
}
#endif  // TOKEN_H