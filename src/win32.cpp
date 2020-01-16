#include <iostream>
#include <vector>
#include <tuple>
#include "win32.h"
#include <psapi.h>
#include <sddl.h>
#include <wtsapi32.h>

namespace win32
{
    void add_access_allowed_ace(PACL acl, uint32_t ace_revision, uint32_t access_mask, PSID sid)
    {
        if (!::AddAccessAllowedAce(acl, ace_revision, access_mask, sid))
        {
            THROW_LAST_ERROR();
        }
    }

    wil::unique_process_heap_ptr<void> adjust_token_privileges(HANDLE token_handle, PTOKEN_PRIVILEGES new_state,
        bool disable_all_privileges)
    {
        wil::unique_process_heap_ptr<void> data(
            ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_PRIVILEGES))
        );
        DWORD return_length = 0;
        ::AdjustTokenPrivileges(token_handle, disable_all_privileges, new_state, sizeof(TOKEN_PRIVILEGES),
            (PTOKEN_PRIVILEGES)data.get(), &return_length);
        DWORD last_err = ::GetLastError();

        if (last_err == ERROR_SUCCESS)
        {
            return data;
        }
        else if (last_err != ERROR_INSUFFICIENT_BUFFER)
        {
            THROW_LAST_ERROR();
        }

        data.reset(::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, return_length));
        if (!::AdjustTokenPrivileges(token_handle, disable_all_privileges, new_state, return_length,
            (PTOKEN_PRIVILEGES)data.get(), &return_length))
        {
            THROW_LAST_ERROR();
        }

        return data;
    }

    LUID allocate_locally_unique_id()
    {
        LUID luid;
        if (!::AllocateLocallyUniqueId(&luid))
        {
            THROW_LAST_ERROR();
        }

        return luid;
    }

    std::string convert_sid_to_string_sid(PSID sid)
    {
        wil::unique_hlocal_string sid_buffer;
        if (!::ConvertSidToStringSidW(sid, &sid_buffer))
        {
            THROW_LAST_ERROR();
        }

        return wide_char_to_multi_byte(sid_buffer.get());
    }

    wil::unique_hlocal convert_string_sid_to_sid(const std::string &string_sid)
    {
        std::wstring w_string_sid = multi_byte_to_wide_char(string_sid);
        wil::unique_hlocal sid;
        if (!::ConvertStringSidToSidW(w_string_sid.c_str(), &sid))
        {
            THROW_LAST_ERROR();
        }

        return sid;
    }

    win32::unique_environment create_environment_block(HANDLE token, bool inherit)
    {
        win32::unique_environment environment;
        if (!::CreateEnvironmentBlock((PVOID *)&environment, token, inherit))
        {
            THROW_LAST_ERROR();
        }

        return environment;
    }

    wil::unique_process_information create_process(const std::string &application_name,
        const std::string &command_line, PSECURITY_ATTRIBUTES process_attributes,
        PSECURITY_ATTRIBUTES thread_attributes, bool inherit_handles, uint32_t creation_flags, PVOID environment,
        std::optional<std::string> current_directory, PVOID startup_info)
    {
        return create_process_as_user(nullptr, application_name, command_line, process_attributes, thread_attributes,
            inherit_handles, creation_flags, environment, current_directory, startup_info);
    }

    wil::unique_process_information create_process_as_user(HANDLE token, const std::string &application_name,
        const std::string &command_line, PSECURITY_ATTRIBUTES process_attributes,
        PSECURITY_ATTRIBUTES thread_attributes, bool inherit_handles, uint32_t creation_flags, PVOID environment,
        std::optional<std::string> current_directory, PVOID startup_info)
    {
        std::wstring w_application_name = multi_byte_to_wide_char(application_name);
        std::wstring w_command_line = multi_byte_to_wide_char(command_line);

        LPCWSTR working_dir = nullptr;
        if (current_directory)
        {
            working_dir = (LPCWSTR)multi_byte_to_wide_char(current_directory.value()).c_str();
        }

        wil::unique_process_information process_info;
        bool res;
        if (token == nullptr)
        {
            res = ::CreateProcessW(w_application_name.c_str(), (LPWSTR)&w_command_line.c_str()[0], process_attributes,
                thread_attributes, inherit_handles, creation_flags, environment, working_dir,
                (LPSTARTUPINFOW)startup_info, &process_info);
        }
        else
        {
            res = ::CreateProcessAsUserW(token, w_application_name.c_str(), (LPWSTR)&w_command_line.c_str()[0],
                process_attributes, thread_attributes, inherit_handles, creation_flags, environment, working_dir,
                (LPSTARTUPINFOW)startup_info, &process_info);
        }
        
        if (!res)
        {
            THROW_LAST_ERROR();
        }

        return process_info;
    }

    wil::unique_handle duplicate_token_ex(HANDLE existing_token, uint32_t desired_access,
        PSECURITY_ATTRIBUTES token_attributes, SECURITY_IMPERSONATION_LEVEL impersonation_level,
        TOKEN_TYPE token_type)
    {
        wil::unique_handle dup_handle;
        if (!::DuplicateTokenEx(existing_token, desired_access, token_attributes, impersonation_level, token_type,
            &dup_handle))
        {
            THROW_LAST_ERROR();
        }

        return dup_handle;
    }

    std::vector<uint32_t> enum_processes()
    {
        std::vector<uint32_t> pids;

        DWORD buffer_size = 128;
        while (true)
        {
            pids.resize(buffer_size);

            DWORD returned_length = 0;
            DWORD current_length = sizeof(pids[0]) * buffer_size;
            if (!::EnumProcesses((DWORD *)&pids[0], current_length, &returned_length))
            {
                THROW_LAST_ERROR();
            }

            if (current_length == returned_length)
            {
                // Continue again but with a larger buffer.
                buffer_size += 128;
                continue;
            }
            else
            {
                // Remove any leftover entries that are no longer needed.
                pids.resize(returned_length / sizeof(pids[0]));
                break;
            }
        }

        return pids;
    }

    bool equal_sid(PSID sid1, PSID sid2)
    {
        return ::EqualSid(sid1, sid2);
    }

    template <typename acl_information>
    acl_information get_acl_information(PACL acl)
    {
        throw std::invalid_argument("invalid ACL information structure specified.");
    }

    template<>
    ACL_SIZE_INFORMATION get_acl_information<ACL_SIZE_INFORMATION>(PACL acl)
    {
        ACL_SIZE_INFORMATION information;
        if (!::GetAclInformation(acl, &information, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
        {
            THROW_LAST_ERROR();
        }

        return information;
    }

    template<>
    ACL_REVISION_INFORMATION get_acl_information<ACL_REVISION_INFORMATION>(PACL acl)
    {
        ACL_REVISION_INFORMATION information;
        if (!::GetAclInformation(acl, &information, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation))
        {
            THROW_LAST_ERROR();
        }

        return information;
    }

    wil::unique_process_handle get_current_process()
    {
        return wil::unique_process_handle(::GetCurrentProcess());
    }

    uint32_t get_current_process_id()
    {
        return ::GetCurrentProcessId();
    }

    wil::unique_handle get_current_thread()
    {
        return wil::unique_handle(::GetCurrentThread());
    }

    std::tuple<wil::unique_hlocal_security_descriptor, PSID, PSID, PACL, PACL> get_security_info(HANDLE handle,
        SE_OBJECT_TYPE object_type, uint32_t security_info)
    {
        PSID owner;
        PSID group;
        PACL dacl;
        PACL sacl;
        wil::unique_hlocal_security_descriptor sd;
        THROW_IF_WIN32_ERROR(::GetSecurityInfo(handle, object_type, security_info, &owner, &group, &dacl, &sacl,
            (PSECURITY_DESCRIPTOR *)&sd));

        return std::make_tuple (std::move(sd), owner, group, dacl, sacl);
    }

    wil::unique_process_heap_ptr<void> get_token_information(HANDLE token_handle, TOKEN_INFORMATION_CLASS info_class)
    {
        DWORD token_information_length = 0;
        ::GetTokenInformation(token_handle, info_class, nullptr, 0,
                &token_information_length);
        DWORD last_err = ::GetLastError();
        if (last_err != ERROR_INSUFFICIENT_BUFFER && last_err != ERROR_BAD_LENGTH)
        {
            THROW_LAST_ERROR();
        }

        wil::unique_process_heap_ptr<void> data(
            ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, token_information_length)
        );

        if (!::GetTokenInformation(token_handle, info_class, data.get(),
            token_information_length, &token_information_length))
        {
            THROW_LAST_ERROR();
        }

        return data;
    }

    wil::unique_process_heap_ptr<void> get_windows_account_domain_sid(PSID sid)
    {
        DWORD sid_length = 0;
        ::GetWindowsAccountDomainSid(sid, nullptr, &sid_length);

        wil::unique_process_heap_ptr<void> data(
            ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sid_length)
        );

        if (!::GetWindowsAccountDomainSid(sid, data.get(), &sid_length))
        {
            THROW_LAST_ERROR();
        }

        return data;
    }

    void impersonate_logged_on_user(HANDLE token)
    {
        if (!::ImpersonateLoggedOnUser(token))
        {
            THROW_LAST_ERROR();
        }
    }

    void impersonate_self(SECURITY_IMPERSONATION_LEVEL impersonation_level)
    {
        if (!::ImpersonateSelf(impersonation_level))
        {
            THROW_LAST_ERROR();
        }
    }

    wil::unique_handle logon_user(const std::string &username, const std::string &domain, const std::string &password,
        uint32_t logon_type, uint32_t logon_provider)
    {
        std::wstring w_username = multi_byte_to_wide_char(username);
        std::wstring w_domain = multi_byte_to_wide_char(domain);
        std::wstring w_password = multi_byte_to_wide_char(password);

        wil::unique_handle p_token;
        if (!::LogonUserW(w_username.c_str(), w_domain.c_str(), w_password.c_str(), logon_type, logon_provider,
            &p_token))
        {
            THROW_LAST_ERROR();
        }

        return p_token;
    }

    std::tuple<wil::unique_process_heap_ptr<void>, std::string, SID_NAME_USE> lookup_account_name(
        const std::string &system_name, const std::string &account_name)
    {
        std::wstring w_system_name = multi_byte_to_wide_char(system_name);
        std::wstring w_account_name = multi_byte_to_wide_char(account_name);

        DWORD sid_length = 0;
        DWORD domain_length = 0;
        SID_NAME_USE name_use;
        ::LookupAccountNameW(w_system_name.c_str(), w_account_name.c_str(), nullptr, &sid_length, nullptr,
            &domain_length, &name_use);

        wil::unique_process_heap_ptr<void> data(
            ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sid_length)
        );
        std::vector<wchar_t> domain_buffer(domain_length);

        if (!::LookupAccountNameW(w_system_name.c_str(), w_account_name.c_str(), data.get(), &sid_length,
            &domain_buffer[0], &domain_length, &name_use))
        {
            THROW_LAST_ERROR();
        }

        std::wstring w_domain(domain_buffer.begin(), domain_buffer.end() - 1);
        return std::make_tuple ((wil::unique_process_heap_ptr<void>)data.release(), wide_char_to_multi_byte(w_domain),
            name_use);
    }

    std::tuple<std::string, std::string, SID_NAME_USE> lookup_account_sid(const std::string &system_name, PSID sid)
    {
        std::wstring w_system_name = multi_byte_to_wide_char(system_name);

        DWORD name_size = 0;
        DWORD domain_size = 0;
        SID_NAME_USE name_use;
        ::LookupAccountSidW(w_system_name.c_str(), sid, nullptr, &name_size, nullptr, &domain_size, &name_use);

        std::vector<wchar_t> name_buffer(name_size);
        std::vector<wchar_t> domain_buffer(domain_size);
        if (!::LookupAccountSidW(w_system_name.c_str(), sid, &name_buffer[0], &name_size, &domain_buffer[0],
            &domain_size, &name_use))
        {
            THROW_LAST_ERROR();
        }

        std::tuple<std::string, std::string, SID_NAME_USE> account_info ("", "", name_use);
        if (name_size > 0)
        {
            std::wstring w_name(name_buffer.begin(), name_buffer.end() - 1);
            std::get<0>(account_info) = wide_char_to_multi_byte(w_name);
        }

        if (domain_size > 0)
        {
            std::wstring w_domain(domain_buffer.begin(), domain_buffer.end() - 1);
            std::get<1>(account_info) = wide_char_to_multi_byte(w_domain);
        }
        
        return account_info;
    }

    std::string lookup_privilege_name(const std::string &system_name, PLUID luid)
    {
        std::wstring w_system_name = multi_byte_to_wide_char(system_name);

        DWORD name_size = 0;
        ::LookupPrivilegeNameW(w_system_name.c_str(), luid, nullptr, &name_size);

        std::vector<wchar_t> name_buffer(name_size);
        if (!::LookupPrivilegeNameW(w_system_name.c_str(), luid, &name_buffer[0], &name_size))
        {
            THROW_LAST_ERROR();
        }

        std::wstring w_name(name_buffer.begin(), name_buffer.end() - 1);

        return wide_char_to_multi_byte(w_name);
    }

    LUID lookup_privilege_value(const std::string &system_name, const std::string &name)
    {
        std::wstring w_system_name = multi_byte_to_wide_char(system_name);
        std::wstring w_name = multi_byte_to_wide_char(name);

        LUID luid;
        if (!::LookupPrivilegeValueW(w_system_name.c_str(), w_name.c_str(), &luid))
        {
            THROW_LAST_ERROR();
        }

        return luid;
    }

    std::tuple<wil::unique_handle, LUID, QUOTA_LIMITS, wil::unique_lsa_ptr<void>, uint32_t> lsa_logon_user(
        HANDLE lsa_handle, const std::string origin_name, SECURITY_LOGON_TYPE logon_type, uint32_t auth_package,
        PVOID auth_info, uint32_t auth_info_length, PTOKEN_GROUPS local_groups, PTOKEN_SOURCE source_context)
    {
        LSA_STRING lsa_origin_name = {
            (USHORT)origin_name.size() * sizeof(char),
            (USHORT)(origin_name.size() * sizeof(char)) + sizeof(char),
            (LPSTR)origin_name.c_str(),
        };

        wil::unique_lsa_ptr<void> profile_buffer;
        ULONG profile_buffer_length = 0;
        LUID logon_id = {};
        wil::unique_handle logon_token;
        QUOTA_LIMITS quotas = {};
        NTSTATUS sub_status = 0;

        NTSTATUS res = ::LsaLogonUser(lsa_handle, &lsa_origin_name, logon_type, auth_package, auth_info,
            auth_info_length, local_groups, source_context, (PVOID *)&profile_buffer, &profile_buffer_length,
            &logon_id, &logon_token, &quotas, &sub_status);

        THROW_IF_NTSTATUS_FAILED_MSG(res, "SubStatus %d", sub_status);

        return std::make_tuple (std::move(logon_token), logon_id, quotas, std::move(profile_buffer),
            profile_buffer_length);
    }

    uint32_t lsa_lookup_authentication_package(HANDLE lsa_handle, const std::string package_name)
    {
        if (!(package_name.size() > 0 && package_name.size() < 127))
        {
            throw std::invalid_argument("LSA package name must be 1 to 127 chars long.");
        }

        LSA_STRING lsa_package_name = {
            lsa_package_name.Length = (USHORT)(package_name.size() * sizeof(char)),
            lsa_package_name.MaximumLength = (USHORT)((package_name.size() * sizeof(char)) + sizeof(char)),
            lsa_package_name.Buffer = (LPSTR)package_name.c_str(),
        };

        uint32_t authentication_package;
        THROW_IF_NTSTATUS_FAILED(::LsaLookupAuthenticationPackage(lsa_handle, &lsa_package_name,
            (PULONG)&authentication_package));

        return authentication_package;
    }

    win32::unique_hlsa lsa_open_policy(const std::string &system_name, uint32_t desired_access)
    {
        PLSA_UNICODE_STRING p_system_name = nullptr;
        if (system_name.size() > 0)
        {
            std::wstring w_system_name = win32::multi_byte_to_wide_char(system_name);
            p_system_name->Buffer = (LPWSTR)w_system_name.c_str();
            p_system_name->Length = (USHORT)(w_system_name.size() * sizeof(wchar_t));
            p_system_name->MaximumLength = (USHORT)((w_system_name.size() * sizeof(wchar_t)) + sizeof(wchar_t));
        }

        LSA_OBJECT_ATTRIBUTES object_attributes = {};
        win32::unique_hlsa policy_handle;
        THROW_IF_NTSTATUS_FAILED(::LsaOpenPolicy(p_system_name, &object_attributes, desired_access, &policy_handle));

        return policy_handle;
    }

    win32::unique_lsamem_ptr lsa_query_information_policy(LSA_HANDLE policy_handle,
        POLICY_INFORMATION_CLASS information_class)
    {
        win32::unique_lsamem_ptr buffer;
        THROW_IF_NTSTATUS_FAILED(::LsaQueryInformationPolicy(policy_handle, information_class, (PVOID *)&buffer));

        return buffer;
    }

    win32::unique_lsa_logon lsa_register_logon_process(const std::string &logon_process_name)
    {
        if (!(logon_process_name.size() > 0 && logon_process_name.size() < 128))
        {
            throw std::invalid_argument("LSA logon process name must be 1 to 127 chars long.");
        }

        LSA_STRING lsa_logon_name;
        lsa_logon_name.Buffer = (LPSTR)logon_process_name.c_str();
        lsa_logon_name.Length = (USHORT)logon_process_name.size();
        lsa_logon_name.MaximumLength = (USHORT)logon_process_name.size() + 1;
        
        win32::unique_lsa_logon logon;
        LSA_OPERATIONAL_MODE op_mode;
        THROW_IF_NTSTATUS_FAILED(::LsaRegisterLogonProcess(&lsa_logon_name, &logon, &op_mode));
        return logon;
    }

    std::wstring multi_byte_to_wide_char(const std::string &str)
    {
        std::wstring converted_string;

        int required_size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, 0, 0);
        if (required_size > 0)
        {
            std::vector<wchar_t> buffer(required_size);
            MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &buffer[0], required_size);
            converted_string.assign(buffer.begin(), buffer.end() - 1);
        }
    
        return converted_string;
    }

    wil::unique_hdesk open_desktop(const std::string &desktop, uint32_t flags, bool inherit, uint32_t desired_access)
    {
        std::wstring w_desktop = multi_byte_to_wide_char(desktop);
        wil::unique_hdesk h(::OpenDesktopW(w_desktop.c_str(), flags, inherit, desired_access));
        if (!h)
        {
            THROW_LAST_ERROR();
        }

        return h;
    }

    wil::unique_process_handle open_process(uint32_t desired_access, bool inherit_handle, uint32_t process_id)
    {
        wil::unique_process_handle h(::OpenProcess(desired_access, inherit_handle, process_id));
        if (!h.is_valid())
        {
            THROW_LAST_ERROR();
        }

        return h;
    }

    wil::unique_handle open_process_token(HANDLE process_handle, uint32_t desired_access)
    {
        wil::unique_handle p_token;
        if (!::OpenProcessToken(process_handle, desired_access, &p_token))
        {
            THROW_LAST_ERROR();
        }

        return p_token;
    }

    wil::unique_handle open_thread_token(HANDLE thread_handle, uint32_t desired_access, bool open_as_self)
    {
        wil::unique_handle t_token;
        if (!::OpenThreadToken(thread_handle, desired_access, open_as_self, &t_token))
        {
            THROW_LAST_ERROR();
        }

        return t_token;
    }

    wil::unique_hwinsta open_window_station(const std::string &winsta, bool inherit, uint32_t desired_access)
    {
        std::wstring w_winsta = multi_byte_to_wide_char(winsta);
        wil::unique_hwinsta h (::OpenWindowStationW(w_winsta.c_str(), inherit, desired_access));
        if (!h)
        {
            THROW_LAST_ERROR();
        }

        return h;
    }

    void revert_to_self()
    {
        if (!::RevertToSelf())
        {
            THROW_LAST_ERROR();
        }
    }

    void secure_zero_memory(PVOID ptr, size_t cnt)
    {
        ::SecureZeroMemory(ptr, cnt);
    }

    wil::unique_hlocal set_entries_in_acl(uint32_t explicit_entries_count, PEXPLICIT_ACCESS_W explicit_entries,
        PACL old_acl)
    {
        wil::unique_hlocal new_acl;
        THROW_IF_WIN32_ERROR(::SetEntriesInAclW(explicit_entries_count, explicit_entries, old_acl, (PACL *)&new_acl));

        return new_acl;
    }

    void set_security_info(HANDLE handle, SE_OBJECT_TYPE object_type, uint32_t security_info, PSID owner, PSID group,
        PACL dacl, PACL sacl)
    {
        THROW_IF_WIN32_ERROR(::SetSecurityInfo(handle, object_type, security_info, owner, group, dacl, sacl));
    }

    void set_token_information(HANDLE token_handle, TOKEN_INFORMATION_CLASS info_class, PVOID info,
        uint32_t info_length)
    {
        if (!::SetTokenInformation(token_handle, info_class, info, info_length))
        {
            THROW_LAST_ERROR();
        }
    }

    std::string wide_char_to_multi_byte(const std::wstring &wstr)
    {
        std::string converted_string;

        int required_size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, 0, 0, 0, 0);
        if (required_size > 0)
        {
            std::vector<char> buffer(required_size);
            WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &buffer[0], required_size, 0, 0);
            converted_string.assign(buffer.begin(), buffer.end() - 1);
        }
        return converted_string;
    }

    win32::unique_fs_redirection wow64_disable_wow64_fs_redirection()
    {
        win32::unique_fs_redirection old_value;
        if (!::Wow64DisableWow64FsRedirection(&old_value))
        {
            THROW_LAST_ERROR();
        }

        return old_value;
    }

    wil::unique_handle wts_query_user_token(uint32_t session_id)
    {
        wil::unique_handle token;
        if (!::WTSQueryUserToken(session_id, &token))
        {
            THROW_LAST_ERROR();
        }

        return token;
    }
}
