#pragma once

#include "superiorsec/common.hpp"

#include <string>
#include <vector>

namespace superiorsec {

std::vector<Check> run_audit();
std::string audit_json(const std::vector<Check>& checks);
std::string audit_text(const std::vector<Check>& checks);

}
