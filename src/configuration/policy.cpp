#include "panopticon/officer/configuration/policy.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <fstream>
#include <set>
#include <span>
#include <stdexcept>
#include <system_error>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace panopticon::officer::configuration {
namespace {
using Json = nlohmann::json;
constexpr char kDomain[] = "PANOPTICON-WINDOWS-CONFIG-V1\0";
constexpr std::array<std::string_view, 9> kFeatures{"process", "network", "dns", "file_integrity", "registry", "powershell", "authentication", "persistence", "memory_inventory"};
constexpr std::uint64_t kMaxLifetime = 30ull * 24 * 60 * 60 * 1000;

struct Alg { BCRYPT_ALG_HANDLE h{}; ~Alg(){ if(h) BCryptCloseAlgorithmProvider(h,0); } };
struct Key { BCRYPT_KEY_HANDLE h{}; ~Key(){ if(h) BCryptDestroyKey(h); } };
struct Hash { BCRYPT_HASH_HANDLE h{}; ~Hash(){ if(h) BCryptDestroyHash(h); } };
struct Mem { void* p{}; ~Mem(){ if(p) LocalFree(p); } };
struct File { HANDLE h{INVALID_HANDLE_VALUE}; ~File(){ if(h!=INVALID_HANDLE_VALUE) CloseHandle(h); } };
struct PolicyLock {
    File file; OVERLAPPED overlap{}; bool locked{};
    explicit PolicyLock(const std::filesystem::path& state){
        const auto path=state.wstring()+L".lock";
        file.h=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_HIDDEN,nullptr);
        if(file.h==INVALID_HANDLE_VALUE)throw std::runtime_error("cannot open policy serialization lock");
        if(!LockFileEx(file.h,LOCKFILE_EXCLUSIVE_LOCK,0,1,0,&overlap))throw std::runtime_error("cannot acquire policy serialization lock");
        locked=true;
    }
    ~PolicyLock(){if(locked)UnlockFileEx(file.h,0,1,0,&overlap);}
};

std::string hex(std::span<const std::uint8_t> b) {
    constexpr char d[]="0123456789abcdef"; std::string s(b.size()*2,'0');
    for(std::size_t i=0;i<b.size();++i){s[i*2]=d[b[i]>>4];s[i*2+1]=d[b[i]&15];} return s;
}
std::vector<std::uint8_t> sha(std::span<const std::uint8_t> b) {
    Alg a; if(BCryptOpenAlgorithmProvider(&a.h,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0) throw std::runtime_error("SHA-256 provider unavailable");
    DWORD n=0,r=0; if(BCryptGetProperty(a.h,BCRYPT_OBJECT_LENGTH,(PUCHAR)&n,sizeof(n),&r,0)<0||r!=sizeof(n)) throw std::runtime_error("SHA-256 object query failed");
    std::vector<std::uint8_t> obj(n),out(32); Hash h;
    if(BCryptCreateHash(a.h,&h.h,obj.data(),n,nullptr,0,0)<0) throw std::runtime_error("SHA-256 initialization failed");
    if(!b.empty()&&BCryptHashData(h.h,const_cast<PUCHAR>(b.data()),static_cast<ULONG>(b.size()),0)<0) throw std::runtime_error("SHA-256 update failed");
    if(BCryptFinishHash(h.h,out.data(),static_cast<ULONG>(out.size()),0)<0) throw std::runtime_error("SHA-256 finalization failed"); return out;
}
std::vector<std::uint8_t> base64(const std::string& s) {
    DWORD n=0; if(s.empty()||s.size()>1024||!CryptStringToBinaryA(s.data(),(DWORD)s.size(),CRYPT_STRING_BASE64,nullptr,&n,nullptr,nullptr)||n!=64) throw std::runtime_error("signature must be 64-byte base64 ECDSA P-256");
    std::vector<std::uint8_t> out(n); if(!CryptStringToBinaryA(s.data(),(DWORD)s.size(),CRYPT_STRING_BASE64,out.data(),&n,nullptr,nullptr)||n!=out.size()) throw std::runtime_error("malformed signature base64"); return out;
}
bool keys_are(const Json& j,std::initializer_list<std::string_view> names){if(!j.is_object()||j.size()!=names.size())return false;for(auto n:names)if(!j.contains(std::string(n)))return false;return true;}
std::uint64_t uint_field(const Json& j,const char* n){if(!j.contains(n)||!j[n].is_number_unsigned())throw std::runtime_error(std::string("invalid unsigned field: ")+n);return j[n].get<std::uint64_t>();}
class JsonGuard {
    std::string_view s; std::size_t p{};
    void ws(){while(p<s.size()&&(s[p]==' '||s[p]=='\t'||s[p]=='\r'||s[p]=='\n'))++p;}
    std::string string(){const auto begin=p++;while(p<s.size()){if(s[p]=='\\'){p+=2;continue;}if(s[p++]=='"'){const std::string token(s.substr(begin,p-begin));return Json::parse(token).get<std::string>();}}throw std::runtime_error("unterminated JSON string");}
    void value(unsigned depth){
        ws();if(depth>32||p>=s.size())throw std::runtime_error("JSON nesting or input bound exceeded");
        if(s[p]=='{'){++p;ws();std::set<std::string> seen;if(p<s.size()&&s[p]=='}'){++p;return;}for(;;){ws();if(p>=s.size()||s[p]!='"')throw std::runtime_error("malformed JSON object key");auto k=string();if(!seen.insert(k).second)throw std::runtime_error("duplicate JSON object key");ws();if(p>=s.size()||s[p++]!=':')throw std::runtime_error("malformed JSON object");value(depth+1);ws();if(p<s.size()&&s[p]==','){++p;continue;}if(p<s.size()&&s[p]=='}'){++p;return;}throw std::runtime_error("malformed JSON object");}}
        if(s[p]=='['){++p;ws();if(p<s.size()&&s[p]==']'){++p;return;}for(;;){value(depth+1);ws();if(p<s.size()&&s[p]==','){++p;continue;}if(p<s.size()&&s[p]==']'){++p;return;}throw std::runtime_error("malformed JSON array");}}
        if(s[p]=='"'){(void)string();return;}while(p<s.size()&&s[p]!=','&&s[p]!=']'&&s[p]!='}'&&s[p]!=' '&&s[p]!='\t'&&s[p]!='\r'&&s[p]!='\n')++p;
    }
public:
    explicit JsonGuard(std::string_view input):s(input){}
    void validate(){value(0);ws();if(p!=s.size())throw std::runtime_error("trailing JSON data");}
};

struct Policy {Json envelope,doc;std::string payload,digest;std::uint64_t gen{},issued{},expires{};};
void validate_shape(const Json& d){
    if(!keys_are(d,{"schema_version","generation","issued_at_unix_ms","expires_at_unix_ms","features","limits"})||!d["schema_version"].is_number_unsigned()||d["schema_version"].get<unsigned>()!=1)throw std::runtime_error("unknown policy schema or field set");
    const auto& f=d["features"];if(!f.is_object()||f.size()!=kFeatures.size())throw std::runtime_error("features must contain the closed version 1 feature set");
    for(auto n:kFeatures)if(!f.contains(std::string(n))||!f[std::string(n)].is_boolean())throw std::runtime_error("missing or non-boolean feature");
    const auto& l=d["limits"];if(!keys_are(l,{"collection_interval_ms","max_batch_events","max_payload_bytes","sampling_per_mille"}))throw std::runtime_error("unknown limits field set");
    auto i=uint_field(l,"collection_interval_ms"),b=uint_field(l,"max_batch_events"),p=uint_field(l,"max_payload_bytes"),s=uint_field(l,"sampling_per_mille");
    if(i<100||i>86400000||!b||b>10000||p<4096||p>8*1024*1024||s>1000)throw std::runtime_error("policy limit outside fixed safe bounds");
}
void reject_weakening(const Json& old,const Json& next){
    for(auto n:kFeatures)if(old["features"][std::string(n)].get<bool>()&&!next["features"][std::string(n)].get<bool>())throw std::runtime_error("policy weakening refused: enabled collection cannot be disabled");
    const auto& a=old["limits"];const auto& b=next["limits"];
    if(uint_field(b,"sampling_per_mille")<uint_field(a,"sampling_per_mille")||uint_field(b,"collection_interval_ms")>uint_field(a,"collection_interval_ms")||uint_field(b,"max_batch_events")<uint_field(a,"max_batch_events")||uint_field(b,"max_payload_bytes")<uint_field(a,"max_payload_bytes"))throw std::runtime_error("policy weakening refused: sampling, collection interval, and resource ceilings are monotonic");
}
Policy verify(std::string_view raw,const std::vector<TrustKey>& trust,std::uint64_t now,bool check_expiry=true){
    if(raw.empty()||raw.size()>kMaximumEnvelopeBytes)throw std::runtime_error("envelope empty or exceeds 256 KiB");
    JsonGuard(raw).validate();Policy p;p.envelope=Json::parse(raw.begin(),raw.end());
    if(!keys_are(p.envelope,{"format","key_id","payload","signature"})||!p.envelope["format"].is_string()||p.envelope["format"]!="panopticon_signed_policy_v1"||!p.envelope["key_id"].is_string()||!p.envelope["payload"].is_string()||!p.envelope["signature"].is_string())throw std::runtime_error("unknown signed envelope format or field set");
    auto id=p.envelope["key_id"].get<std::string>();p.payload=p.envelope["payload"].get<std::string>();if(p.payload.empty()||p.payload.size()>kMaximumPayloadBytes)throw std::runtime_error("payload empty or exceeds 128 KiB");
    const TrustKey* pin=nullptr;for(const auto& k:trust)if(k.key_id==id){pin=&k;break;}if(!pin)throw std::runtime_error("signing key is not pinned");
    if(pin->subject_public_key_info_der.empty()||pin->subject_public_key_info_der.size()>4096||hex(sha(pin->subject_public_key_info_der))!=pin->key_id)throw std::runtime_error("pinned SPKI fingerprint or size is invalid");
    Mem info_mem;DWORD cb=0;if(!CryptDecodeObjectEx(X509_ASN_ENCODING,X509_PUBLIC_KEY_INFO,pin->subject_public_key_info_der.data(),(DWORD)pin->subject_public_key_info_der.size(),CRYPT_DECODE_ALLOC_FLAG,nullptr,&info_mem.p,&cb))throw std::runtime_error("pinned SPKI DER cannot be decoded");
    auto* info=static_cast<CERT_PUBLIC_KEY_INFO*>(info_mem.p);if(!info->Algorithm.pszObjId||std::string_view(info->Algorithm.pszObjId)!=szOID_ECC_PUBLIC_KEY)throw std::runtime_error("pinned key is not elliptic-curve public key");
    Key key;if(!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,info,0,nullptr,&key.h))throw std::runtime_error("Windows CNG could not import pinned key");
    wchar_t name[64]{};DWORD got=0;if(BCryptGetProperty(key.h,BCRYPT_ALGORITHM_NAME,(PUCHAR)name,sizeof(name),&got,0)<0||std::wstring_view(name)!=BCRYPT_ECDSA_P256_ALGORITHM)throw std::runtime_error("pinned key must be ECDSA P-256");
    std::vector<std::uint8_t> msg;msg.reserve(sizeof(kDomain)-1+p.payload.size());msg.insert(msg.end(),(const std::uint8_t*)kDomain,(const std::uint8_t*)kDomain+sizeof(kDomain)-1);msg.insert(msg.end(),p.payload.begin(),p.payload.end());
    auto digest=sha(msg),sig=base64(p.envelope["signature"].get<std::string>());if(BCryptVerifySignature(key.h,nullptr,digest.data(),(ULONG)digest.size(),sig.data(),(ULONG)sig.size(),0)<0)throw std::runtime_error("signature verification failed");p.digest=hex(digest);
    JsonGuard(p.payload).validate();p.doc=Json::parse(p.payload);validate_shape(p.doc);p.gen=uint_field(p.doc,"generation");p.issued=uint_field(p.doc,"issued_at_unix_ms");p.expires=uint_field(p.doc,"expires_at_unix_ms");
    if(!p.gen||!p.issued||p.expires<=p.issued||p.expires-p.issued>kMaxLifetime)throw std::runtime_error("invalid generation or policy lifetime");
    if(p.issued>now&&p.issued-now>300000)throw std::runtime_error("policy issue time is too far in the future");if(check_expiry&&now>=p.expires)throw std::runtime_error("policy expired");return p;
}
struct State {bool exists{};std::uint64_t high{};std::string digest,desired,effective,rollback;std::set<std::string> active;bool rolled{};};
State load(const std::filesystem::path& path){
    State s;std::error_code ec;if(!std::filesystem::exists(path,ec)){if(ec)throw std::runtime_error("cannot inspect state file");return s;}auto n=std::filesystem::file_size(path,ec);if(ec||!n||n>1024*1024)throw std::runtime_error("state file unreadable or out of bounds");
    std::ifstream in(path,std::ios::binary);if(!in)throw std::runtime_error("cannot open state file");std::string raw((std::size_t)n,'\0');in.read(raw.data(),(std::streamsize)n);if(!in||in.peek()!=std::char_traits<char>::eof())throw std::runtime_error("incomplete state file");auto j=Json::parse(raw);
    if(!keys_are(j,{"format","highest_generation","highest_digest","desired_envelope","effective_envelope","rollback_envelope","effective_features","rolled_back"})||j["format"]!="panopticon_policy_state_v2"||!j["highest_digest"].is_string()||!j["desired_envelope"].is_string()||!j["effective_envelope"].is_string()||!j["rollback_envelope"].is_string()||!j["effective_features"].is_array()||!j["rolled_back"].is_boolean())throw std::runtime_error("malformed state schema");
    s.high=uint_field(j,"highest_generation");s.digest=j["highest_digest"].get<std::string>();s.desired=j["desired_envelope"].get<std::string>();s.effective=j["effective_envelope"].get<std::string>();s.rollback=j["rollback_envelope"].get<std::string>();s.rolled=j["rolled_back"].get<bool>();for(const auto& f:j["effective_features"]){if(!f.is_string()||std::find(kFeatures.begin(),kFeatures.end(),f.get<std::string>())==kFeatures.end()||!s.active.insert(f.get<std::string>()).second)throw std::runtime_error("invalid effective feature state");}if(!s.high||s.digest.size()!=64||s.desired.empty()||s.effective.empty())throw std::runtime_error("incomplete state record");s.exists=true;return s;
}
Json state_json(std::uint64_t gen,const std::string& digest,const std::string& desired,const std::string& effective,const std::string& rollback,const std::set<std::string>& active,bool rolled){return Json{{"format","panopticon_policy_state_v2"},{"highest_generation",gen},{"highest_digest",digest},{"desired_envelope",desired},{"effective_envelope",effective},{"rollback_envelope",rollback},{"effective_features",active},{"rolled_back",rolled}};}
void atomic_save(const std::filesystem::path& target,const Json& j){
    auto parent=target.parent_path();if(parent.empty()||!std::filesystem::is_directory(parent))throw std::runtime_error("state parent must already exist and be service-owned");auto raw=j.dump();if(raw.size()>1024*1024)throw std::runtime_error("serialized state exceeds 1 MiB");auto temp=target.wstring()+L"."+std::to_wstring(GetCurrentProcessId())+L"."+std::to_wstring(GetTickCount64())+L".next";
    File f;f.h=CreateFileW(temp.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_TEMPORARY,nullptr);if(f.h==INVALID_HANDLE_VALUE)throw std::runtime_error("cannot create policy state temporary file");std::size_t off=0;
    try{while(off<raw.size()){DWORD ask=(DWORD)std::min<std::size_t>(raw.size()-off,1u<<20),written=0;if(!WriteFile(f.h,raw.data()+off,ask,&written,nullptr)||written!=ask)throw std::runtime_error("policy state write failed");off+=written;}if(!FlushFileBuffers(f.h))throw std::runtime_error("policy state flush failed");}catch(...){DeleteFileW(temp.c_str());throw;}
    CloseHandle(f.h);f.h=INVALID_HANDLE_VALUE;DWORD attr=GetFileAttributesW(target.c_str());BOOL ok=attr==INVALID_FILE_ATTRIBUTES&&GetLastError()==ERROR_FILE_NOT_FOUND?MoveFileExW(temp.c_str(),target.c_str(),MOVEFILE_WRITE_THROUGH):ReplaceFileW(target.c_str(),temp.c_str(),nullptr,0,nullptr,nullptr);
    if(!ok){DWORD e=GetLastError();DeleteFileW(temp.c_str());throw std::system_error((int)e,std::system_category(),"atomic state replacement failed");}
    File committed;committed.h=CreateFileW(target.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(committed.h==INVALID_HANDLE_VALUE||!FlushFileBuffers(committed.h))throw std::runtime_error("state replacement is visible but final durability confirmation failed");
}
std::vector<FeatureState> statuses(const Json& desired,const Json* effective,const std::set<std::string>& active,const std::vector<std::string>& supported,bool authorized=true){
    std::set<std::string> cap(supported.begin(),supported.end());std::vector<FeatureState> out;for(auto v:kFeatures){std::string n(v);bool d=desired["features"][n].get<bool>(),e=authorized&&d&&effective&&cap.contains(n)&&active.contains(n)&&(*effective)["features"][n].get<bool>();std::string state=!authorized?"unauthorized":!d?"disabled":!cap.contains(n)?"unsupported":e?"active":"pending";out.push_back({n,d,e,std::move(state)});}return out;
}
Snapshot snapshot_of(const State& s,const std::vector<TrustKey>& trust,std::uint64_t now,const std::vector<std::string>& caps){
    Snapshot o;o.highest_accepted_generation=s.high;if(!s.exists){o.error="no authorized policy has been activated";for(auto n:kFeatures)o.features.push_back({std::string(n),false,false,"unauthorized"});return o;}
    auto d=verify(s.desired,trust,now,false);if(d.gen!=s.high||d.digest!=s.digest)throw std::runtime_error("state high-water record mismatch");o.desired_generation=d.gen;o.policy_digest=d.digest;
    if(now>=d.expires){o.policy_expired=true;o.error="desired policy expired; all collection remains disabled";o.features=statuses(d.doc,nullptr,{},caps);for(auto& f:o.features){f.effective=false;f.state="expired";}return o;}
    auto e=verify(s.effective,trust,now,false);if(e.gen>d.gen)throw std::runtime_error("effective policy is newer than desired");for(const auto& active:s.active)if(!e.doc["features"][active].get<bool>())throw std::runtime_error("effective state claims a feature excluded by its signed policy");o.authorized=true;o.rolled_back=s.rolled;o.effective_generation=e.gen;
    if(now>=e.expires){o.error="effective policy expired; collection must remain disabled";o.features=statuses(d.doc,nullptr,{},caps);for(auto& f:o.features){f.effective=false;if(f.desired)f.state="expired";}return o;}
    o.features=statuses(d.doc,&e.doc,s.active,caps);return o;
}
} // namespace

PolicyStore::PolicyStore(std::filesystem::path path,std::vector<TrustKey> trust):state_file_(std::filesystem::absolute(std::move(path)).lexically_normal()),trust_keys_(std::move(trust)){
    if(trust_keys_.empty()||trust_keys_.size()>kMaximumTrustKeys)throw std::invalid_argument("trust set must contain 1..8 pinned keys");std::set<std::string> ids;for(const auto& k:trust_keys_)if(k.key_id.size()!=64||k.subject_public_key_info_der.empty()||k.subject_public_key_info_der.size()>4096||!ids.insert(k.key_id).second)throw std::invalid_argument("invalid, duplicate, or oversized trust key");
}
Result PolicyStore::activate(std::string_view raw,std::uint64_t now,const std::vector<std::string>& caps){
    Result r;try{PolicyLock lock(state_file_);auto s=load(state_file_);auto next=verify(raw,trust_keys_,now);if(s.exists){auto old=verify(s.desired,trust_keys_,now,false);if(old.gen!=s.high||old.digest!=s.digest)throw std::runtime_error("durable high-water record mismatch");if(next.gen<s.high)throw std::runtime_error("replay refused: generation below high-water mark");if(next.gen==s.high){if(next.digest!=s.digest)throw std::runtime_error("fork refused: same generation has different signed content");r.accepted=true;r.snapshot=snapshot_of(s,trust_keys_,now,caps);return r;}reject_weakening(old.doc,next.doc);}
        auto state=state_json(next.gen,next.digest,std::string(raw),std::string(raw),s.exists?s.effective:std::string{},s.active,false);atomic_save(state_file_,state);State saved{true,next.gen,next.digest,std::string(raw),std::string(raw),s.exists?s.effective:std::string{},s.active,false};r.accepted=true;r.changed=true;r.snapshot=snapshot_of(saved,trust_keys_,now,caps);
    }catch(const std::exception& e){r.snapshot.error=e.what();try{r.snapshot.highest_accepted_generation=load(state_file_).high;}catch(...){}}return r;
}
Result PolicyStore::rollback(std::uint64_t now,const std::vector<std::string>& caps){
    Result r;try{PolicyLock lock(state_file_);auto s=load(state_file_);if(!s.exists||s.rollback.empty())throw std::runtime_error("no previous valid effective policy for rollback");auto d=verify(s.desired,trust_keys_,now,false),old=verify(s.rollback,trust_keys_,now),cur=verify(s.effective,trust_keys_,now,false);if(d.gen!=s.high||d.digest!=s.digest||old.gen>=cur.gen)throw std::runtime_error("rollback target or high-water state invalid");reject_weakening(cur.doc,old.doc);for(const auto& active:s.active)if(!old.doc["features"][active].get<bool>())throw std::runtime_error("rollback would deactivate an effective collection feature");auto j=state_json(s.high,s.digest,s.desired,s.rollback,s.effective,s.active,true);atomic_save(state_file_,j);s.effective=s.rollback;s.rollback=cur.envelope.dump();s.rolled=true;r.accepted=true;r.changed=true;r.snapshot=snapshot_of(s,trust_keys_,now,caps);
    }catch(const std::exception& e){r.snapshot.error=e.what();try{r.snapshot.highest_accepted_generation=load(state_file_).high;}catch(...){}}return r;
}
Result PolicyStore::confirm_effective(std::uint64_t generation,const std::vector<std::string>& actual,std::uint64_t now,const std::vector<std::string>& caps){
    Result r;try{PolicyLock lock(state_file_);auto s=load(state_file_);if(!s.exists)throw std::runtime_error("no authorized desired policy");auto d=verify(s.desired,trust_keys_,now);auto e=verify(s.effective,trust_keys_,now);if(d.gen!=s.high||d.digest!=s.digest||generation!=s.high)throw std::runtime_error("effective confirmation generation is stale or inconsistent");
        std::set<std::string> supported(caps.begin(),caps.end()),active;for(const auto& name:actual){if(std::find(kFeatures.begin(),kFeatures.end(),name)==kFeatures.end()||!active.insert(name).second)throw std::runtime_error("effective feature list contains an unknown or duplicate name");if(!supported.contains(name)||!d.doc["features"][name].get<bool>()||!e.doc["features"][name].get<bool>())throw std::runtime_error("effective feature was not desired, supported, and authorized by both policy views");}
        s.active=std::move(active);auto j=state_json(s.high,s.digest,s.desired,s.effective,s.rollback,s.active,s.rolled);atomic_save(state_file_,j);r.accepted=true;r.changed=true;r.snapshot=snapshot_of(s,trust_keys_,now,caps);
    }catch(const std::exception& e){r.snapshot.error=e.what();try{r.snapshot.highest_accepted_generation=load(state_file_).high;}catch(...){}}return r;
}
Snapshot PolicyStore::current(std::uint64_t now,const std::vector<std::string>& caps)const{try{PolicyLock lock(state_file_);return snapshot_of(load(state_file_),trust_keys_,now,caps);}catch(const std::exception& e){Snapshot s;s.error=e.what();return s;}}
} // namespace panopticon::officer::configuration
