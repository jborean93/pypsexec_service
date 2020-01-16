#ifndef WIN32_H
#define WIN32_H
#include <iostream>
#include <optional>
#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>
#include <ntsecapi.h>
#include <userenv.h>
#include "wil\resource.h"

namespace win32
{
    using unique_environment = wil::unique_any<PVOID, decltype(&::DestroyEnvironmentBlock), ::DestroyEnvironmentBlock>;

    using unique_hlsa = wil::unique_any<LSA_HANDLE, decltype(&::LsaClose), ::LsaClose>;

    using unique_lsa_logon = wil::unique_any<HANDLE, decltype(&::LsaDeregisterLogonProcess),
        ::LsaDeregisterLogonProcess>;

    using unique_lsamem_ptr = wil::unique_any<PVOID, decltype(&::LsaFreeMemory), LsaFreeMemory>;

    using unique_fs_redirection = wil::unique_any<PVOID, decltype(&::Wow64RevertWow64FsRedirection),
        ::Wow64RevertWow64FsRedirection, wil::details::pointer_access_all, PVOID, PVOID, (PVOID)-1>;

    void add_access_allowed_ace(PACL acl, uint32_t ace_revision, uint32_t access_mask, PSID sid);

    wil::unique_process_heap_ptr<void> adjust_token_privileges(HANDLE token_handle, PTOKEN_PRIVILEGES new_state,
        bool disable_all_privileges);

    LUID allocate_locally_unique_id();

    std::string convert_sid_to_string_sid(PSID sid);

    wil::unique_hlocal convert_string_sid_to_sid(const std::string &string_sid);

    win32::unique_environment create_environment_block(HANDLE token, bool inherit);

    wil::unique_process_information create_process(const std::string &application_name,
        const std::string &command_line, PSECURITY_ATTRIBUTES process_attributes,
        PSECURITY_ATTRIBUTES thread_attributes, bool inherit_handles, uint32_t creation_flags, PVOID environment,
        std::optional<std::string> current_directory, PVOID startup_info);

    wil::unique_process_information create_process_as_user(HANDLE token, const std::string &application_name,
        const std::string &command_line, PSECURITY_ATTRIBUTES process_attributes,
        PSECURITY_ATTRIBUTES thread_attributes, bool inherit_handles, uint32_t creation_flags, PVOID environment,
        std::optional<std::string> current_directory, PVOID startup_info);

    wil::unique_handle duplicate_token_ex(HANDLE existing_token, uint32_t desired_access,
        PSECURITY_ATTRIBUTES token_attributes, SECURITY_IMPERSONATION_LEVEL impersonation_level,
        TOKEN_TYPE token_type);

    std::vector<uint32_t> enum_processes();

    bool equal_sid(PSID sid1, PSID sid2);

    template <typename acl_information>
    acl_information get_acl_information(PACL acl);

    wil::unique_process_handle get_current_process();

    uint32_t get_current_process_id();

    wil::unique_handle get_current_thread();

    std::tuple<wil::unique_hlocal_security_descriptor, PSID, PSID, PACL, PACL> get_security_info(HANDLE handle,
        SE_OBJECT_TYPE object_type, uint32_t security_info);

    wil::unique_process_heap_ptr<void> get_token_information(HANDLE token_handle, TOKEN_INFORMATION_CLASS info_class);

    wil::unique_process_heap_ptr<void> get_windows_account_domain_sid(PSID sid);

    void impersonate_logged_on_user(HANDLE token);

    void impersonate_self(SECURITY_IMPERSONATION_LEVEL impersonation_level = SecurityImpersonation);

    wil::unique_handle logon_user(const std::string &username, const std::string &domain, const std::string &password,
        uint32_t logon_type, uint32_t logon_provider);

    std::tuple<wil::unique_process_heap_ptr<void>, std::string, SID_NAME_USE> lookup_account_name(
        const std::string &system_name, const std::string &account_name);

    std::tuple<std::string, std::string, SID_NAME_USE> lookup_account_sid(const std::string &system_name, PSID sid);

    std::string lookup_privilege_name(const std::string &system_name, PLUID luid);

    LUID lookup_privilege_value(const std::string &system_name, const std::string &name);

    std::tuple<wil::unique_handle, LUID, QUOTA_LIMITS, wil::unique_lsa_ptr<void>, uint32_t> lsa_logon_user(
        HANDLE lsa_handle, const std::string origin_name, SECURITY_LOGON_TYPE logon_type, uint32_t auth_package,
        PVOID auth_info, uint32_t auth_info_length, PTOKEN_GROUPS local_groups, PTOKEN_SOURCE source_context);

    uint32_t lsa_lookup_authentication_package(HANDLE lsa_handle, const std::string package_name);

    win32::unique_hlsa lsa_open_policy(const std::string &system_name, uint32_t desired_access);

    win32::unique_lsamem_ptr lsa_query_information_policy(LSA_HANDLE policy_handle,
        POLICY_INFORMATION_CLASS information_class);

    win32::unique_lsa_logon lsa_register_logon_process(const std::string &logon_process_name);

    std::wstring multi_byte_to_wide_char(const std::string &str);

    wil::unique_hdesk open_desktop(const std::string &desktop, uint32_t flags, bool inherit, uint32_t desired_access);

    wil::unique_process_handle open_process(uint32_t desired_access, bool inherit_handle, uint32_t process_id);

    wil::unique_handle open_process_token(HANDLE process_handle, uint32_t desired_access);

    wil::unique_handle open_thread_token(HANDLE thread_handle, uint32_t desired_access, bool open_as_self);

    wil::unique_hwinsta open_window_station(const std::string &winsta, bool inherit, uint32_t desired_access);

    void revert_to_self();

    void secure_zero_memory(PVOID ptr, size_t cnt);

    wil::unique_hlocal set_entries_in_acl(uint32_t explicit_entries_count, PEXPLICIT_ACCESS_W explicit_entries,
        PACL old_acl);

    void set_security_info(HANDLE handle, SE_OBJECT_TYPE object_type, uint32_t security_info, PSID owner, PSID group,
        PACL dacl, PACL sacl);

    void set_token_information(HANDLE token_handle, TOKEN_INFORMATION_CLASS info_class, PVOID info,
        uint32_t info_length);

    std::string wide_char_to_multi_byte(const std::wstring &wstr);

    win32::unique_fs_redirection wow64_disable_wow64_fs_redirection();

    wil::unique_handle wts_query_user_token(uint32_t session_id);
}
#endif
