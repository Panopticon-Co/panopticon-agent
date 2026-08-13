#include "eyetrace/sysmon_parser.hpp"

#include <fstream>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

std::string read_fixture(const char* name) {
    std::ifstream file(std::string(EYETRACE_FIXTURE_DIR) + "/" + name);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

void test_process_create() {
    std::string error;
    const auto event = eyetrace::SysmonParser::parse_xml(read_fixture("sysmon_process_create.xml"), error);
    expect(event.has_value(), "process fixture parses");
    if (event) {
        expect(event->category == "process" && event->type == "create", "process category and type");
        expect(event->process.pid == 4242, "process PID");
        expect(event->parent.pid == 1000, "parent PID");
        expect(event->process.command_line.has_value(), "process command line");
    }
}

void test_network_file_and_registry() {
    std::string error;
    const auto network = eyetrace::SysmonParser::parse_xml(read_fixture("sysmon_network_connect.xml"), error);
    expect(network && network->network && network->network->destination_port == 443, "network fields parse");
    const auto file = eyetrace::SysmonParser::parse_xml(read_fixture("sysmon_file_create.xml"), error);
    expect(file && file->file && file->file->path.has_value(), "file fields parse");
    const auto registry = eyetrace::SysmonParser::parse_xml(read_fixture("sysmon_registry_value_set.xml"), error);
    expect(registry && registry->registry && registry->registry->operation == "SetValue", "registry fields parse");

    std::string registry_xml = read_fixture("sysmon_registry_value_set.xml");
    registry_xml.replace(registry_xml.find("<EventID>13"), std::string("<EventID>13").size(), "<EventID>12");
    const auto registry_create_delete = eyetrace::SysmonParser::parse_xml(registry_xml, error);
    expect(registry_create_delete && registry_create_delete->type == "create_or_delete", "registry Event ID 12 dispatches");
    registry_xml.replace(registry_xml.find("<EventID>12"), std::string("<EventID>12").size(), "<EventID>14");
    const auto registry_rename = eyetrace::SysmonParser::parse_xml(registry_xml, error);
    expect(registry_rename && registry_rename->type == "rename", "registry Event ID 14 dispatches");
}

void test_missing_and_invalid_values() {
    std::string xml = read_fixture("sysmon_process_create.xml");
    const std::string command_line = "<Data Name=\"CommandLine\">&quot;C:\\TelemetryLab\\sample.exe&quot; --safe-test</Data>\n    ";
    xml.erase(xml.find(command_line), command_line.size());
    std::string error;
    const auto missing = eyetrace::SysmonParser::parse_xml(xml, error);
    expect(missing && !missing->process.command_line.has_value(), "missing optional command line is safe");

    xml = read_fixture("sysmon_process_create.xml");
    const auto position = xml.find(">4242<");
    xml.replace(position, 6, ">not-a-number<");
    error.clear();
    expect(!eyetrace::SysmonParser::parse_xml(xml, error).has_value() && error.find("ProcessId") != std::string::npos,
           "invalid numeric field fails explicitly");

    error.clear();
    expect(!eyetrace::SysmonParser::parse_xml("<Event>", error).has_value() && !error.empty(), "malformed XML fails safely");
}

}  // namespace

int main() {
    test_process_create();
    test_network_file_and_registry();
    test_missing_and_invalid_values();
    if (failures == 0) {
        std::cout << "All parser tests passed.\n";
        return 0;
    }
    return 1;
}
