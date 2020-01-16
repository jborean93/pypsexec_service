#include <iostream>
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

   message::error error_msg;
   error_msg.error_code = 256;
   error_msg.message = u8"Howdy ho - café";
   auto error_bytes = error_msg.serialize();

   std::optional<uint32_t> session_id = 3;

#ifndef NDEBUG
    // When testing this locally we need to impersonate a SYSTEM token for various API calls to work.
    token_helper::impersonate_system();
#endif

    // SeTcbPrivilege is required for S4U or logons with custom groups. It's also used to get the linked token.
    std::vector<token_helper::privilege_state> privileges;
    privileges.push_back({"SeTcbPrivilege", SE_PRIVILEGE_ENABLED});
    token_helper::set_privileges(privileges);

    // Get the primary token for the session specified.
    // TODO: Catch ERROR_NO_TOKEN and return better error message.
    wil::unique_handle session_token = win32::wts_query_user_token(session_id.value());
    auto session_logon_sid_buffer = win32::get_token_information(session_token.get(), TokenLogonSid);

    // Log on the new user.
    //wil::unique_handle logon_token = token_helper::logon_user("vagrant", "vagrant");
    wil::unique_handle logon_token = token_helper::logon_user("standard-domain@DOMAIN.LOCAL", "Password01",
        LOGON32_LOGON_INTERACTIVE, (PTOKEN_GROUPS)session_logon_sid_buffer.get());

    token_helper::set_session_id(logon_token.get(), session_id.value());

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

    return 0;
}
