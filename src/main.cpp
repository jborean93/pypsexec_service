#include <iostream>
#include <memory>
#include <sstream>
#include "token.h"
#include "message.h"
#include "win32.h"

int main(int argc, char** argv)
{
    /*
        If interactive
            -i
                Does not seem to work remotely but -id 0 does, go figure.

            -i <id>
                Interactive
                The logon session SID is different
                Session ID is <id>
                Medium level token, unless -h is used
    
        else
            run in the console session as is - interactive with explicit, passthru if no cred
    */

    message::error error_msg (10, u8"Howdy ho - café");
    auto error_bytes = error_msg.serialize();

    uint32_t pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS;
    auto pipe_handle = win32::create_named_pipe("\\\\.\\pipe\\Jordan", PIPE_ACCESS_DUPLEX, pipe_mode, 1, 1024, 1024,
        0, nullptr);
    win32::connect_named_pipe(pipe_handle.get(), nullptr);

    bool res = ::ImpersonateNamedPipeClient(pipe_handle.get());
    auto pipe_token = win32::open_thread_token(win32::get_current_thread().get(), TOKEN_QUERY | TOKEN_DUPLICATE, true);
    win32::revert_to_self();

    auto cloned_token = win32::duplicate_token_ex(pipe_token.get(), TOKEN_QUERY | TOKEN_DUPLICATE, nullptr, SecurityImpersonation, TokenPrimary);
    pipe_token.reset(cloned_token.release());

    auto token_stat_buffer = win32::get_token_information(pipe_token.get(), TokenStatistics);
    PTOKEN_STATISTICS token_stat = (PTOKEN_STATISTICS)token_stat_buffer.get();

    auto token_user_buffer = win32::get_token_information(pipe_token.get(), TokenUser);
    PTOKEN_USER token_user = (PTOKEN_USER)token_user_buffer.get();
    auto token_user_str = win32::convert_sid_to_string_sid(token_user->User.Sid);
    auto token_user_info = win32::lookup_account_sid("", token_user->User.Sid);

    win32::write_file(pipe_handle.get(), error_bytes.data(), error_bytes.size(), nullptr);

    std::string a = "";

    /*

    std::optional<uint32_t> session_id = 2;
    std::optional<std::string> service_name = "TrustedInstaller";
    std::string username = "SYSTEM";
    std::optional<std::string> password = std::nullopt;
    uint32_t logon_type = LOGON32_LOGON_SERVICE;

#ifndef NDEBUG
    // When testing this locally we need to impersonate a SYSTEM token for various API calls to work.
    token_helper::impersonate_system();
#endif

    // SeTcbPrivilege is required for S4U or logons with custom groups. It's also used to get the linked token.
    std::vector<token_helper::privilege_state> privileges;
    privileges.push_back({"SeTcbPrivilege", SE_PRIVILEGE_ENABLED});
    token_helper::set_privileges(privileges);

    // TODO: see why the LOCAL group is not being added
    std::unique_ptr<std::byte[]> token_groups_buffer;
    wil::unique_process_heap_ptr<void> session_logon_sid;
    wil::unique_process_heap_ptr<void> service_sid_buffer;
    PTOKEN_GROUPS token_groups = nullptr;
    if (session_id || service_name)
    {
        int group_count = session_id && service_name ? 2 : 1;
        int token_groups_size = sizeof(TOKEN_GROUPS) + (sizeof(SID_AND_ATTRIBUTES) * (group_count - 1));
        token_groups_buffer = std::make_unique<std::byte[]>(token_groups_size);
        token_groups = (PTOKEN_GROUPS)token_groups_buffer.get();
        token_groups->GroupCount = group_count;

        int offset = 0;
        if (session_id)
        {
            // Get the primary token for the session specified.
            // TODO: Catch ERROR_NO_TOKEN and return better error message.
            wil::unique_handle session_token = win32::wts_query_user_token(session_id.value());
            session_logon_sid = win32::get_token_information(session_token.get(), TokenLogonSid);
            token_groups->Groups[0].Attributes = ((PTOKEN_GROUPS)session_logon_sid.get())->Groups[0].Attributes;
            token_groups->Groups[0].Sid = ((PTOKEN_GROUPS)session_logon_sid.get())->Groups[0].Sid;

            offset++;
        }

        if (service_name)
        {
            auto service_info = win32::lookup_account_name("", "NT SERVICE\\" + service_name.value());
            service_sid_buffer = std::move(std::get<0>(service_info));
            token_groups->Groups[offset].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER;
            token_groups->Groups[offset].Sid = (PSID)service_sid_buffer.get();
        }
    }

    // Log on the new user.
    //wil::unique_handle logon_token = token_helper::logon_user("vagrant", "vagrant");
    //wil::unique_handle logon_token = token_helper::logon_user("standard-domain@DOMAIN.LOCAL", "Password01",
    //    LOGON32_LOGON_INTERACTIVE, (PTOKEN_GROUPS)session_logon_sid.get());
    auto logon_token = token_helper::logon_user(username, password, logon_type, token_groups);

    if (session_id)
    {
        token_helper::set_session_id(logon_token.get(), session_id.value());
    }

    // Start the new process.
    auto env_block = win32::create_environment_block(logon_token.get(), false);

    STARTUPINFOEXW si = {};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    si.StartupInfo.lpTitle = (LPWSTR)L"Test title";
    si.StartupInfo.lpDesktop = (LPWSTR)L"WinSta0\\Default";
    uint32_t creation_flags = CREATE_UNICODE_ENVIRONMENT | CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_CONSOLE;

    bool redir = true;
    win32::unique_fs_redirection fs_redir;
    if (redir)
    {
        fs_redir = win32::wow64_disable_wow64_fs_redirection();
    }
    auto proc_info = win32::create_process_as_user(logon_token.get(), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "", nullptr, nullptr, false,
        creation_flags, env_block.get(), "C:\\Users", &si);
    fs_redir.reset();  // Make sure we disable file redirection as soon as possible

    std::string a = "";
    */

    return 0;
}
