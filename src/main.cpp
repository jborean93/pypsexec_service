#include <iostream>
#include <sstream>
#include "token.h"
#include "security_descriptor.h"
#include "win32.h"

/*
std::vector<std::string> get_env_block(HANDLE handle, bool load_own)
{
    std::vector<std::string> env_vars;

    auto env = win32::create_environment_block(handle, load_own);

    wchar_t* current_entry = (wchar_t*)env.get();
    do
    {
        std::string entry = win32::wide_char_to_multi_byte(current_entry);
        env_vars.push_back(entry);
        std::cout << entry << "\n";
        current_entry += wcslen(current_entry) + 1;
    }
    while(*current_entry);

    std::cout << "\n";

    return env_vars;
}
*/

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

#ifndef NDEBUG
    // When testing this locally we need to impersonate a SYSTEM token for various API calls to work.
    token_helper::impersonate_system();
#endif

    uint32_t session_id = 3;

    // SeTcbPrivilege is required for S4U or logons with custom groups. It's also used to get the linked token.
    std::vector<token_helper::privilege_state> privileges;
    privileges.push_back({"SeTcbPrivilege", SE_PRIVILEGE_ENABLED});
    token_helper::set_privileges(privileges);

    // Get the primary token for the session specified.
    // TODO: Catch ERROR_NO_TOKEN and return better error message.
    wil::unique_handle session_token = win32::wts_query_user_token(session_id);
    auto session_logon_sid_buffer = win32::get_token_information(session_token.get(), TokenLogonSid);
    PSID session_logon_sid = ((PTOKEN_GROUPS)session_logon_sid_buffer.get())->Groups[0].Sid;
    std::string session_logon_sid_str = win32::convert_sid_to_string_sid(session_logon_sid);

    auto current_logon_token = win32::open_process_token(win32::get_current_process().get(), TOKEN_QUERY);
    auto current_logon_sid_buffer = win32::get_token_information(current_logon_token.get(), TokenLogonSid);
    PSID current_logon_sid = ((PTOKEN_GROUPS)current_logon_sid_buffer.get())->Groups[0].Sid;
    std::string current_logon_sid_str = win32::convert_sid_to_string_sid(current_logon_sid);

    // Log on the new user.
    //wil::unique_handle logon_token = token_helper::logon_user("vagrant", "vagrant");
    wil::unique_handle logon_token = token_helper::logon_user("standard-domain@DOMAIN.LOCAL", "Password01", LOGON32_LOGON_INTERACTIVE,
        (PTOKEN_GROUPS)session_logon_sid_buffer.get());

    token_helper::set_session_id(logon_token.get(), session_id);

    // Get the logon session ID SID.
    auto logon_sid_buffer = win32::get_token_information(logon_token.get(), TokenLogonSid);
    PSID logon_sid = ((PTOKEN_GROUPS)logon_sid_buffer.get())->Groups[0].Sid;
    std::string logon_sid_str = win32::convert_sid_to_string_sid(logon_sid);

    auto logon_id_buffer = win32::get_token_information(logon_token.get(), TokenSessionId);
    uint32_t logon_id = *((uint32_t *)logon_id_buffer.get());

    // Grant access to the logon session ID SID to the current station/desktop so a Window will appear.
    //auto station_sd = sd::open_window_station_sd("WinSta0", DACL_SECURITY_INFORMATION);
    //station_sd.add_ace_to_dacl({logon_sid, GENERIC_ALL, SET_ACCESS, NO_INHERITANCE});
    //station_sd.persist();
    
    //auto desktop_sd = sd::open_desktop_sd("Default", DACL_SECURITY_INFORMATION);
    //desktop_sd.add_ace_to_dacl({logon_sid, GENERIC_ALL, SET_ACCESS, NO_INHERITANCE});
    //desktop_sd.persist();

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

    //station_sd.add_ace_to_dacl({logon_sid, GENERIC_ALL, REVOKE_ACCESS, NO_INHERITANCE});
    //station_sd.persist();

    //desktop_sd.add_ace_to_dacl({logon_sid, GENERIC_ALL, REVOKE_ACCESS, NO_INHERITANCE});
    //desktop_sd.persist();

    std::string a = "";

    return 0;
}
