#include "panopticon/officer/response/identity.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace panopticon::officer::response {

namespace {

// Best-effort ACL lockdown: grant the current process token's owner
// Full Control and remove inherited/other ACEs, mirroring the intent of the
// Linux agent's `chmod 600`. Failure to lock down is reported but is not
// itself treated as fatal to writing the file -- matching the Linux agent,
// which also cannot fully guarantee a hostile local admin can't read root-
// owned files anyway; the real trust boundary is "not group/world readable
// by default", not "immune to a privileged attacker on the same host".
bool restrict_to_current_user(const std::wstring& path, std::string& error_message) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error_message = "cannot open process token to restrict identity file ACL";
        return false;
    }
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::vector<unsigned char> buffer(needed);
    const bool have_user =
        needed != 0 && GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed) != FALSE;
    PSID user_sid = have_user ? reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid : nullptr;
    if (!have_user || user_sid == nullptr) {
        CloseHandle(token);
        error_message = "cannot resolve current user SID to restrict identity file ACL";
        return false;
    }

    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = GENERIC_ALL;
    access.grfAccessMode = SET_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(user_sid);

    PACL new_acl = nullptr;
    const DWORD result = SetEntriesInAclW(1, &access, nullptr, &new_acl);
    CloseHandle(token);
    if (result != ERROR_SUCCESS || new_acl == nullptr) {
        error_message = "cannot build a restrictive ACL for the identity file";
        return false;
    }
    const DWORD applied = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, user_sid, nullptr, new_acl, nullptr);
    LocalFree(new_acl);
    if (applied != ERROR_SUCCESS) {
        error_message = "cannot apply a restrictive ACL to the identity file";
        return false;
    }
    return true;
}

}  // namespace

bool is_valid_identifier(const std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](const unsigned char character) {
        return std::isalnum(character) != 0 || character == '-' || character == '_' || character == '.';
    });
}

std::optional<EnrolledIdentity> load_enrolled_identity(const std::filesystem::path& path,
                                                        std::string& error_message) {
    std::ifstream input{path};
    std::string agent_id;
    std::string host_id;
    std::string token;
    if (!input || !std::getline(input, agent_id) || !std::getline(input, host_id) ||
        !std::getline(input, token) || !is_valid_identifier(agent_id) || !is_valid_identifier(host_id) ||
        token.empty() || token.size() > 512U) {
        error_message = "enrolled identity is absent or invalid";
        return std::nullopt;
    }
    return EnrolledIdentity{std::move(agent_id), std::move(host_id), std::move(token)};
}

bool store_enrolled_identity(const std::filesystem::path& path, const EnrolledIdentity& identity,
                              std::string& error_message) {
    if (!is_valid_identifier(identity.agent_id) || !is_valid_identifier(identity.host_id) ||
        identity.bearer_token.empty() || identity.bearer_token.size() > 512U) {
        error_message = "enrolled identity is invalid";
        return false;
    }
    std::error_code filesystem_error;
    std::filesystem::create_directories(path.parent_path(), filesystem_error);
    if (filesystem_error) {
        error_message = "cannot create identity directory";
        return false;
    }
    const auto temporary = path.string() + ".tmp";
    {
        std::ofstream output{temporary, std::ios::trunc};
        if (!output) {
            error_message = "cannot write enrolled identity";
            return false;
        }
        output << identity.agent_id << '\n' << identity.host_id << '\n' << identity.bearer_token << '\n';
        output.flush();
        if (!output) {
            error_message = "cannot persist enrolled identity";
            return false;
        }
    }
    std::string acl_error;
    if (!restrict_to_current_user(std::filesystem::path{temporary}.wstring(), acl_error)) {
        // Non-fatal: still publish the file (see comment above), but surface
        // the ACL failure through error_message for the caller to log.
        error_message = acl_error;
    }
    std::filesystem::rename(temporary, path, filesystem_error);
    if (filesystem_error) {
        std::filesystem::remove(temporary, filesystem_error);
        error_message = "cannot publish enrolled identity";
        return false;
    }
    return true;
}

}  // namespace panopticon::officer::response
