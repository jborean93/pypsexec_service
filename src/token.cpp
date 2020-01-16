#include <cstddef>
#include "token.h"
#include <security.h>

const std::vector<std::string> SERVICE_SIDS {"S-1-5-18", "S-1-5-19", "S-1-5-20"};

std::tuple<std::string, std::string, std::string> normalize_username(const std::string &username)
{
    // First lookup the SID of the username and get the domain SID part.
    auto account_lookup = win32::lookup_account_name("", username);
    PSID account_sid = (PSID)std::move(std::get<0>(account_lookup)).get();
    std::string account_sid_str = win32::convert_sid_to_string_sid(account_sid);

    // Convert the SID back to a user/domain string to normalize the string.
    auto account_info = win32::lookup_account_sid("", account_sid);

    return std::make_tuple(std::get<0>(account_info), std::get<1>(account_info), account_sid_str);
}

UNICODE_STRING init_unicode_string(const std::wstring &wstr, const std::unique_ptr<std::byte[]> &buffer,
    int buffer_size, int &offset)
{
    USHORT length = (USHORT)wstr.size() * sizeof(wchar_t);
    UNICODE_STRING uni_string = {
        length,
        length,
        (LPWSTR)0,
    };

    uni_string.Buffer = (LPWSTR)(buffer.get() + offset);
    wmemcpy_s(uni_string.Buffer, buffer_size - offset, wstr.c_str(), wstr.size());

    offset = offset + length;

    return uni_string;
}

namespace token_helper
{
    void impersonate_system()
    {
        wil::unique_hlocal system_sid = win32::convert_string_sid_to_sid("S-1-5-18");

        // Ensure SeDebugPrivilege is enabled so we can interrogate other process tokens.
        win32::impersonate_self();
        std::vector<token_helper::privilege_state> debug_enable;
        debug_enable.push_back({"SeDebugPrivilege", SE_PRIVILEGE_ENABLED});
        token_helper::set_privileges(debug_enable);

        for (auto const &pid: win32::enum_processes())
        {
            wil::unique_process_handle proc_handle;
            try
            {
                proc_handle = win32::open_process(PROCESS_QUERY_INFORMATION, false, pid);
            }
            catch (const wil::ResultException &e)
            {
                continue;
            }

            wil::unique_handle proc_token;
            try
            {
                proc_token = win32::open_process_token(proc_handle.get(), TOKEN_QUERY | TOKEN_DUPLICATE);
            }
            catch (const wil::ResultException &e)
            {
                continue;
            }

            auto proc_user_buffer = win32::get_token_information(proc_token.get(), TokenUser);
            PTOKEN_USER proc_user = (PTOKEN_USER)proc_user_buffer.get();

            if (!win32::equal_sid(proc_user->User.Sid, (PSID)system_sid.get()))
            {
                continue;
            }

            // Some SYSTEM tokens are missing privileges that we require, this makes sure we duplicate the token that
            // has the SeTcbPrivilege privilege present.
            auto proc_priv_buffer = win32::get_token_information(proc_token.get(), TokenPrivileges);
            PTOKEN_PRIVILEGES proc_priv = (PTOKEN_PRIVILEGES)proc_priv_buffer.get();
            bool priv_found = false;
            for (int i = 0; i < proc_priv->PrivilegeCount; i++)
            {
                LUID priv_luid = proc_priv->Privileges[i].Luid;
                std::string privilege_name = win32::lookup_privilege_name("", &priv_luid);
                if (privilege_name == "SeTcbPrivilege")
                {
                    priv_found = true;
                    break;
                }
            }

            if (!priv_found)
            {
                continue;
            }

            wil::unique_handle dup_token = win32::duplicate_token_ex(proc_token.get(), TOKEN_QUERY | TOKEN_DUPLICATE,
                nullptr, SecurityImpersonation, TokenPrimary);

            win32::revert_to_self();  // Exits the ImpersonateSelf() call made earlier.
            win32::impersonate_logged_on_user(dup_token.get());
            return;
        }

        win32::revert_to_self();
        throw std::exception("Failed to find SYSTEM token to impersonate");
    }

    wil::unique_handle logon_user(const std::string &username, std::optional<std::string> password,
        uint32_t logon_type, PTOKEN_GROUPS groups)
    {
        auto [user_part, domain_part, sid] = normalize_username(username);
        std::wstring w_user = win32::multi_byte_to_wide_char(user_part);
        std::wstring w_domain = win32::multi_byte_to_wide_char(domain_part);

        auto lsa_handle = win32::lsa_register_logon_process("pypsexec service");
        uint32_t auth_package_id = win32::lsa_lookup_authentication_package(lsa_handle.get(), NEGOSSP_NAME_A);

        LUID source_luid = win32::allocate_locally_unique_id();
        std::string source_name = "pypsexec";
        TOKEN_SOURCE source_context = {};
        memcpy_s(&source_context.SourceName[0], 8, source_name.c_str(), source_name.size());
        source_context.SourceIdentifier = source_luid;

        std::unique_ptr<std::byte[]> auth_buffer;
        uint32_t auth_package_length = 0;

        // Override the logon type and password if the account is a well known service account.
        if (std::find(std::begin(SERVICE_SIDS), std::end(SERVICE_SIDS), sid) != std::end(SERVICE_SIDS))
        {
            logon_type = LOGON32_LOGON_SERVICE;
            password = "";
        }
        
        if (!password)
        {
            if (logon_type == 0)
            {
                logon_type = LOGON32_LOGON_BATCH;
            }

            auth_package_length = sizeof(MSV1_0_S4U_LOGON) + ((w_user.size() + w_domain.size()) * sizeof(wchar_t));
            auth_buffer.reset(new std::byte[auth_package_length]);

            int offset = sizeof(MSV1_0_S4U_LOGON);
            PMSV1_0_S4U_LOGON auth_package = (PMSV1_0_S4U_LOGON)auth_buffer.get();
            auth_package->MessageType = MsV1_0S4ULogon;
            auth_package->Flags = 0;
            auth_package->UserPrincipalName = init_unicode_string(w_user, auth_buffer, auth_package_length, offset);
            auth_package->DomainName = init_unicode_string(w_domain, auth_buffer, auth_package_length, offset);
        }
        else
        {
            if (logon_type == 0)
            {
                logon_type = LOGON32_LOGON_INTERACTIVE;
            }

            std::wstring w_password = win32::multi_byte_to_wide_char(password.value());

            auto cred_length = ((w_user.size() + w_domain.size() + w_password.size()) * sizeof(wchar_t));
            auth_package_length = sizeof(MSV1_0_INTERACTIVE_LOGON) + cred_length;
            auth_buffer.reset(new std::byte[auth_package_length]);

            int offset = sizeof(MSV1_0_INTERACTIVE_LOGON);
            PMSV1_0_INTERACTIVE_LOGON auth_package = (PMSV1_0_INTERACTIVE_LOGON)auth_buffer.get();
            auth_package->MessageType = MsV1_0InteractiveLogon;
            auth_package->LogonDomainName = init_unicode_string(w_domain, auth_buffer, auth_package_length, offset);
            auth_package->UserName = init_unicode_string(w_user, auth_buffer, auth_package_length, offset);
            auth_package->Password = init_unicode_string(w_password, auth_buffer, auth_package_length, offset);
        }

        auto logon_info = win32::lsa_logon_user(lsa_handle.get(), "PYPSEXEC", (SECURITY_LOGON_TYPE)logon_type,
            auth_package_id, auth_buffer.get(), auth_package_length, groups, &source_context);

        // Ensure credentials have been safely 0'd out now that the buffer has been read.
        win32::secure_zero_memory(auth_buffer.get(), auth_package_length);

        return std::move(std::get<0>(logon_info));
    }

    std::vector<privilege_state> set_privileges(const std::vector<privilege_state> &privileges)
    {
        std::vector<privilege_state> state;

        if (privileges.size() == 0)
            return state;

        auto priv_length = sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * (privileges.size() - 1));
        wil::unique_process_heap_ptr<void> token_privs(::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, priv_length));
        PTOKEN_PRIVILEGES token_privileges = (PTOKEN_PRIVILEGES)token_privs.get();
        token_privileges->PrivilegeCount = privileges.size();

        for (std::vector<privilege_state>::size_type i = 0; i != privileges.size(); i++)
        {
            LUID privilege_luid = win32::lookup_privilege_value("", privileges[i].privilege);
            token_privileges->Privileges[i] = {privilege_luid, privileges[i].attribute};
        }

        uint32_t token_access = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
        wil::unique_handle token;
        try
        {
            token = win32::open_thread_token(win32::get_current_thread().get(), token_access, true);
        }
        catch(const wil::ResultException &e)
        {
            if (e.GetErrorCode() != HRESULT_FROM_WIN32(ERROR_NO_TOKEN))
            {
                throw;
            }
            token = win32::open_process_token(win32::get_current_process().get(), token_access);            
        }

        auto previous_state_ptr = win32::adjust_token_privileges(token.get(), token_privileges, false);
        PTOKEN_PRIVILEGES previous_state = (PTOKEN_PRIVILEGES)previous_state_ptr.get();

        for (int i = 0; i != previous_state->PrivilegeCount; i++)
        {
            std::string privilege_name = win32::lookup_privilege_name("", &previous_state->Privileges[i].Luid);
            state.push_back({privilege_name, previous_state->Privileges[i].Attributes});
        }

        return state;
    }

    void set_session_id(HANDLE token, uint32_t session_id)
    {
        win32::set_token_information(token, TokenSessionId, &session_id, sizeof(uint32_t));
    }
}
