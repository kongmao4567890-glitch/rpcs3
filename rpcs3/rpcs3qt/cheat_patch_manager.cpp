#include "stdafx.h"
#include "cheat_patch_manager.h"

#include "Emu/System.h"
#include "Emu/IdManager.h"
#include "Emu/Memory/vm.h"
#include "Emu/CPU/CPUThread.h"
#include "Emu/NP/np_handler.h"
#include "Utilities/bin_patch.h"
#include "Utilities/File.h"
#include "Utilities/StrUtil.h"
#include "Utilities/Config.h"
#include "util/yaml.hpp"

#include <QHeaderView>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QMessageBox>
#include <QMenu>
#include <QFileDialog>
#include <QFileInfo>
#include <QDir>
#include <QCoreApplication>
#include <QSplitter>
#include <QFrame>

#include <charconv>
#include <algorithm>
#include <cstring>
#include <regex>

// ===========================================================================
// Logging
// ===========================================================================
LOG_CHANNEL(log_cheat_patch);

// ===========================================================================
// fmt_class_string specializations
// ===========================================================================
template <>
void fmt_class_string<cheat_type>::format(std::string& out, u64 arg)
{
	format_enum(out, arg, [](cheat_type value)
	{
		switch (value)
		{
		case cheat_type::normal: return "Normal";
		case cheat_type::constant: return "Constant";
		default: return unknown;
		}
	});
}

template <>
void fmt_class_string<cheat_inst>::format(std::string& out, u64 arg)
{
	format_enum(out, arg, [](cheat_inst value)
	{
		switch (value)
		{
		case cheat_inst::write_bytes: return "write_bytes";
		case cheat_inst::or_bytes: return "or_bytes";
		case cheat_inst::and_bytes: return "and_bytes";
		case cheat_inst::xor_bytes: return "xor_bytes";
		case cheat_inst::write_text: return "write_text";
		case cheat_inst::write_float: return "write_float";
		case cheat_inst::write_condensed: return "write_condensed";
		case cheat_inst::read_pointer: return "read_pointer";
		case cheat_inst::copy: return "copy";
		case cheat_inst::paste: return "paste";
		case cheat_inst::find_replace: return "find_replace";
		case cheat_inst::compare_cond: return "compared_cond";
		case cheat_inst::and_compare_cond: return "and_compare_cond";
		case cheat_inst::copy_bytes: return "copy_bytes";
		default: return unknown;
		}
	});
}

// ===========================================================================
// Global cheat engine instance
// ===========================================================================
cheat_engine g_cheat_engine;

// ===========================================================================
// NCL parser namespace — parses Artemis .NCL cheat files
// Based on PR #11925 ncl_parser
// ===========================================================================
namespace ncl_parser
{
	std::optional<u32> hexstr_to_u32(std::string_view str)
	{
		u32 result;
		if (std::from_chars(str.data(), str.data() + str.size(), result, 16).ec != std::errc())
		{
			log_cheat_patch.warning("Couldn't parse %s into an u32!", str);
			return std::nullopt;
		}
		return result;
	}

	std::optional<cheat_inst> get_type(std::string_view str)
	{
		if (str.empty()) return std::nullopt;

		switch (str[0])
		{
		case '0':
		{
			auto subtype = hexstr_to_u32(str);
			if (!subtype) return std::nullopt;
			switch (*subtype)
			{
			case 0: return cheat_inst::write_bytes;
			case 1: return cheat_inst::or_bytes;
			case 2: return cheat_inst::and_bytes;
			case 3: return cheat_inst::xor_bytes;
			default: return std::nullopt;
			}
		}
		case '1': return cheat_inst::write_text;
		case '2': return cheat_inst::write_float;
		case '4': return cheat_inst::write_condensed;
		case '6': return cheat_inst::read_pointer;
		case 'A':
		{
			auto subtype = hexstr_to_u32(std::string_view(str.data() + 1, str.size() - 1));
			if (!subtype) return std::nullopt;
			switch (*subtype)
			{
			case 1: return cheat_inst::copy;
			case 2: return cheat_inst::paste;
			default: return std::nullopt;
			}
		}
		case 'B': return cheat_inst::find_replace;
		case 'D': return cheat_inst::compare_cond;
		case 'E': return cheat_inst::and_compare_cond;
		case 'F': return cheat_inst::copy_bytes;
		default: return std::nullopt;
		}
	}

	bool validate_hexzstr(std::string_view str)
	{
		return std::all_of(str.begin(), str.end(), [](char c)
		{
			return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') || c == 'Z';
		});
	}

	bool validate_float(std::string_view str)
	{
		char* str_end = nullptr;
		std::strtof(str.data(), &str_end);
		return (str_end == (str.data() + str.size()));
	}

	std::optional<cheat_code> parse_codeline(std::string_view line, std::optional<cheat_code> current_inst = std::nullopt)
	{
		cheat_code code;
		std::vector<std::string> args = fmt::split(line, {" "});
		if (args.size() < 3) return std::nullopt;

		auto type = get_type(args[0]);
		if (!type) return std::nullopt;

		// Special processing for 2-line instructions
		if (current_inst)
		{
			if (current_inst->type != *type) return std::nullopt;
			if (*type == cheat_inst::write_condensed || *type == cheat_inst::find_replace)
			{
				if (!validate_hexzstr(args[1]) || !validate_hexzstr(args[2])) return std::nullopt;
				current_inst->opt1 = args[1];
				current_inst->opt2 = args[2];
				return current_inst;
			}
			return std::nullopt;
		}

		if (!validate_hexzstr(args[1])) return std::nullopt;

		code.type = *type;
		code.addr = args[1];

		switch (code.type)
		{
		case cheat_inst::write_bytes:
		case cheat_inst::or_bytes:
		case cheat_inst::and_bytes:
		case cheat_inst::xor_bytes:
		case cheat_inst::write_condensed:
		case cheat_inst::read_pointer:
		case cheat_inst::copy:
		case cheat_inst::paste:
		case cheat_inst::find_replace:
			if (!validate_hexzstr(args[2])) return std::nullopt;
			break;
		case cheat_inst::write_text:
			break;
		case cheat_inst::write_float:
			if (!validate_float(args[2])) return std::nullopt;
			break;
		case cheat_inst::compare_cond:
		case cheat_inst::and_compare_cond:
		case cheat_inst::copy_bytes:
		{
			if (!validate_hexzstr(std::string_view(args[0].data() + 1, args[0].size() - 1))) return std::nullopt;
			if (!validate_hexzstr(args[2])) return std::nullopt;
			code.opt1 = args[0].data() + 1;
			break;
		}
		default:
			return std::nullopt;
		}

		code.value = args[2];
		return code;
	}

	std::optional<std::pair<std::string, std::map<std::string, std::string>>> parse_variable(std::string_view str)
	{
		if (str.empty() || str[0] != '[') return std::nullopt;

		std::string var_name;
		std::map<std::string, std::string> options;
		std::string cur_name, cur_value;

		auto it = str.begin() + 1;
		for (; it != str.end() && *it == 'Z'; it++)
			var_name += *it;

		if (it == str.end() || var_name.empty() || *it != ']') return std::nullopt;
		it++;

		bool value = true;
		for (; it != str.end(); it++)
		{
			if (*it == ';' || *it == '[')
			{
				options.insert_or_assign(std::move(cur_name), std::move(cur_value));
				cur_name = {};
				cur_value = {};
				value = true;
				continue;
			}
			if (*it == '=')
			{
				value = false;
				continue;
			}
			auto& to_add = value ? cur_value : cur_name;
			to_add += *it;
		}

		return {{var_name, options}};
	}

	std::optional<std::map<std::string, cheat_entry>> parse_ncl(const std::string& file_to_open)
	{
		std::map<std::string, cheat_entry> entries;

		fs::file file(file_to_open);
		if (!file || !file.size()) return std::nullopt;

		std::string buf(file.size(), ' ');
		file.read(buf.data(), buf.size());

		const std::vector<std::string> lines = fmt::split(buf, {"\r\n", "\n"});

		std::string title;
		cheat_entry entry;
		u32 cur_line = 0;
		std::optional<cheat_code> two_liner_code{};

		for (const auto& line : lines)
		{
			if (line == "#")
			{
				if (!entry.codes.empty())
					entries.insert_or_assign(std::move(title), std::move(entry));
				title = {};
				entry = {};
				cur_line = 0;
				two_liner_code = std::nullopt;
				continue;
			}

			switch (cur_line)
			{
			case 0:
				title = line;
				break;
			case 1:
				if (!line.empty())
				{
					if (line[0] == '0') entry.type = cheat_type::normal;
					else if (line[0] == '1' || line[0] == 'T') entry.type = cheat_type::constant;
				}
				break;
			default:
			{
				auto code = parse_codeline(line, two_liner_code);
				if (!code)
				{
					if (cur_line == 2)
					{
						entry.author = line;
						break;
					}
					auto variable = parse_variable(line);
					if (!variable)
					{
						entry.comments.push_back(line);
						break;
					}
					entry.variables.insert_or_assign(variable->first, variable->second);
					break;
				}

				auto type = code->type;
				if (type == cheat_inst::write_condensed || type == cheat_inst::find_replace)
				{
					if (two_liner_code)
					{
						entry.codes.push_back(*code);
						two_liner_code = std::nullopt;
						break;
					}
					two_liner_code = code;
					break;
				}
				entry.codes.push_back(*code);
				break;
			}
			}
			cur_line++;
		}

		return entries;
	}
} // namespace ncl_parser

// ===========================================================================
// cheatsv2.yml code type mapping
// Maps cheatsv2.yml type strings to cheat_inst enum
// ===========================================================================
static cheat_inst v2_type_to_inst(const std::string& type_str)
{
	if (type_str == "write_bytes")     return cheat_inst::write_bytes;
	if (type_str == "or_bytes")        return cheat_inst::or_bytes;
	if (type_str == "and_bytes")       return cheat_inst::and_bytes;
	if (type_str == "xor_bytes")       return cheat_inst::xor_bytes;
	if (type_str == "write_text")      return cheat_inst::write_text;
	if (type_str == "write_float")     return cheat_inst::write_float;
	if (type_str == "write_condensed") return cheat_inst::write_condensed;
	if (type_str == "read_pointer")    return cheat_inst::read_pointer;
	if (type_str == "copy")            return cheat_inst::copy;
	if (type_str == "paste")           return cheat_inst::paste;
	if (type_str == "find_replace")    return cheat_inst::find_replace;
	if (type_str == "compared_cond" || type_str == "compare_cond") return cheat_inst::compare_cond;
	if (type_str == "and_compare_cond") return cheat_inst::and_compare_cond;
	if (type_str == "copy_bytes")      return cheat_inst::copy_bytes;
	return cheat_inst::write_bytes; // default
}

// ===========================================================================
// cheat_executor implementation
// ===========================================================================
cheat_executor::cheat_executor(std::string_view game_name, std::string_view cheat_name,
                               const cheat_entry& entry,
                               std::unordered_map<std::string, std::string> var_choices)
	: m_game_name(game_name), m_cheat_name(cheat_name), m_entry(entry), m_var_choices(var_choices)
{
}

std::pair<const std::string&, const std::string&> cheat_executor::get_name() const
{
	return {m_game_name, m_cheat_name};
}

bool cheat_executor::is(std::string_view game_name, std::string_view cheat_name) const
{
	return (m_game_name == game_name && m_cheat_name == cheat_name);
}

bool cheat_executor::operator<(const cheat_executor& rhs) const
{
	return m_game_name < rhs.m_game_name || m_cheat_name < rhs.m_cheat_name;
}

std::string cheat_executor::parse_value(const std::string& to_parse) const
{
	std::string variable;
	std::string final_string;

	auto check_variable = [&]()
	{
		if (!variable.empty())
		{
			auto it = m_var_choices.find(variable);
			if (it != m_var_choices.end())
				final_string += it->second;
			variable.clear();
		}
	};

	for (auto it = to_parse.begin(); it != to_parse.end(); it++)
	{
		if (*it == 'Z')
		{
			variable += 'Z';
			continue;
		}
		check_variable();
		final_string += *it;
	}
	check_variable();
	return final_string;
}

std::optional<u32> cheat_executor::parse_value_to_u32(const std::string& to_parse) const
{
	const std::string final_str = parse_value(to_parse);
	u32 result;
	if (std::from_chars(final_str.data(), final_str.data() + final_str.size(), result, 16).ec != std::errc())
	{
		// Try decimal
		char* end = nullptr;
		unsigned long val = std::strtoul(final_str.c_str(), &end, 10);
		if (end == final_str.c_str()) return std::nullopt;
		return static_cast<u32>(val);
	}
	return result;
}

std::optional<float> cheat_executor::parse_value_to_float(const std::string& to_parse) const
{
	const std::string final_str = parse_value(to_parse);
	char* str_end = nullptr;
	float result = std::strtof(final_str.data(), &str_end);
	if (str_end != (final_str.data() + final_str.size())) return std::nullopt;
	return result;
}

std::optional<std::vector<u8>> cheat_executor::parse_value_to_vector(const std::string& to_parse) const
{
	std::string final_str = parse_value(to_parse);
	std::vector<u8> result;
	if (final_str.size() % 2 != 0)
		final_str = "0" + final_str;

	for (size_t i = 0; i < final_str.size(); i += 2)
	{
		u8 val;
		if (std::from_chars(final_str.data() + i, final_str.data() + i + 2, val, 16).ec != std::errc())
		{
			log_cheat_patch.error("Failed to parse %s into a vector of bytes!", final_str);
			return std::nullopt;
		}
		result.push_back(val);
	}
	return result;
}

bool cheat_executor::valid_range(u32 addr, u32 size)
{
	const u32 begin = addr - (addr % 4096);
	const u32 end_addr = addr + size;
	const u32 end = end_addr - (end_addr % 4096);

	for (u32 index = begin; index <= end; index += 4096)
	{
		if (!vm::check_addr(index))
			return false;
	}
	return true;
}

bool cheat_executor::execute(bool pause) const
{
	if (Emu.IsStopped())
	{
		log_cheat_patch.error("Attempted to execute a cheat while the emulator was stopped!");
		return false;
	}

	// Don't apply cheats while online
	auto* np = g_fxo->try_get<named_thread<np::np_handler>>();
	if (np && np->get_psn_status() == SCE_NP_MANAGER_STATUS_ONLINE)
		return true;

	log_cheat_patch.notice("Applying cheat '%s':'%s'", m_game_name, m_cheat_name);

	auto apply_cheat = [&]
	{
		u32 ptr_addr = 0;
		usz skip = 0;
		std::vector<u8> copy_buf;

		for (const auto& code : m_entry.codes)
		{
			u32 addr = 0;

			if (skip)
			{
				skip--;
				continue;
			}

			if (ptr_addr)
			{
				addr = ptr_addr;
				ptr_addr = 0;
			}
			else
			{
				auto opt_addr = parse_value_to_u32(code.addr);
				if (!opt_addr) return;
				addr = *opt_addr;
			}

			auto memory_op = [](cheat_inst type, u8* dest, u8* src, u32 size)
			{
				switch (type)
				{
				case cheat_inst::write_bytes:
					std::memcpy(dest, src, size);
					break;
				case cheat_inst::or_bytes:
					for (u32 i = 0; i < size; i++) *(dest + i) |= src[i];
					break;
				case cheat_inst::and_bytes:
					for (u32 i = 0; i < size; i++) *(dest + i) &= src[i];
					break;
				case cheat_inst::xor_bytes:
					for (u32 i = 0; i < size; i++) *(dest + i) ^= src[i];
					break;
				default:
					break;
				}
			};

			switch (code.type)
			{
			case cheat_inst::write_bytes:
			case cheat_inst::or_bytes:
			case cheat_inst::and_bytes:
			case cheat_inst::xor_bytes:
			{
				auto data = parse_value_to_vector(code.value);
				if (!data) return;
				if (!valid_range(addr, static_cast<u32>(data->size())))
				{
					log_cheat_patch.error("Error validating range for %s", code.type);
					return;
				}
				memory_op(code.type, vm::get_super_ptr<u8>(addr), data->data(), static_cast<u32>(data->size()));
				break;
			}
			case cheat_inst::write_text:
			{
				const std::string text = parse_value(code.value);
				if (!valid_range(addr, static_cast<u32>(text.size())))
				{
					log_cheat_patch.error("Error validating range for write_text");
					return;
				}
				std::memcpy(vm::get_super_ptr<u8>(addr), text.c_str(), text.size());
				break;
			}
			case cheat_inst::write_float:
			{
				auto data = parse_value_to_float(code.value);
				if (!data) return;
				if (!valid_range(addr, sizeof(float)))
				{
					log_cheat_patch.error("Error validating range for write_float");
					return;
				}
				*vm::get_super_ptr<be_t<float>>(addr) = *data;
				break;
			}
			case cheat_inst::write_condensed:
			{
				auto data = parse_value_to_vector(code.value);
				auto opt_increment = parse_value_to_u32(code.opt1);
				auto opt_count = parse_value_to_u32(code.opt2);
				if (!data || !opt_increment || !opt_count) return;

				auto increment = *opt_increment;
				auto count = *opt_count;

				if (!valid_range(addr, (increment * count) + static_cast<u32>(data->size())))
				{
					log_cheat_patch.error("Error validating range for write_condensed");
					return;
				}

				u8* ptr = vm::get_super_ptr<u8>(addr);
				for (u32 i = 0; i < count; i++)
					std::memcpy(ptr + (count * increment), data->data(), data->size());
				break;
			}
			case cheat_inst::read_pointer:
			{
				auto increment = parse_value_to_u32(code.value);
				if (!increment) return;
				if (!valid_range(addr, sizeof(u32)))
				{
					log_cheat_patch.error("Error validating range for read_pointer");
					return;
				}
				ptr_addr = (*vm::get_super_ptr<be_t<u32>>(addr)) + *increment;
				break;
			}
			case cheat_inst::copy:
			{
				auto size = parse_value_to_u32(code.value);
				if (!size) return;
				if (!valid_range(addr, *size)) return;
				copy_buf.resize(*size);
				std::memcpy(copy_buf.data(), vm::get_super_ptr<u8>(addr), *size);
				break;
			}
			case cheat_inst::paste:
			{
				auto size = parse_value_to_u32(code.value);
				if (!size) return;
				if (!valid_range(addr, *size)) return;
				if (*size > copy_buf.size()) return;
				std::memcpy(vm::get_super_ptr<u8>(addr), copy_buf.data(), *size);
				break;
			}
			case cheat_inst::find_replace:
			{
				auto end_addr = parse_value_to_u32(code.value);
				auto to_find = parse_value_to_vector(code.opt1);
				auto to_replace = parse_value_to_vector(code.opt2);
				if (!end_addr || !to_find || !to_replace) return;

				u32 search_start = addr;
				u32 search_end = *end_addr;
				if (search_end < search_start) std::swap(search_end, search_start);

				for (u32 i = search_start; i < search_end; i++)
				{
					if (!valid_range(i, static_cast<u32>(to_find->size()))) continue;
					if (std::memcmp(vm::get_super_ptr<u8>(i), to_find->data(), to_find->size()) == 0)
					{
						if (valid_range(i, static_cast<u32>(to_replace->size())))
						{
							std::memcpy(vm::get_super_ptr<u8>(i), to_replace->data(), to_replace->size());
							log_cheat_patch.notice("find_replace: replaced at 0x%x", i);
						}
						break;
					}
				}
				break;
			}
			case cheat_inst::compare_cond:
			{
				auto to_skip = parse_value_to_u32(code.opt1);
				auto data = parse_value_to_vector(code.value);
				if (!to_skip || !data) return;
				if (!valid_range(addr, static_cast<u32>(data->size()))) return;
				if (std::memcmp(vm::get_super_ptr<u8>(addr), data->data(), data->size()) != 0)
					skip = *to_skip;
				break;
			}
			case cheat_inst::and_compare_cond:
			{
				auto to_skip = parse_value_to_u32(code.opt1);
				auto data = parse_value_to_vector(code.value);
				if (!to_skip || !data) return;
				if (!valid_range(addr, static_cast<u32>(data->size()))) return;

				u8* ptr = vm::get_super_ptr<u8>(addr);
				bool matched = true;
				for (usz i = 0; i < data->size(); i++)
				{
					if ((ptr[i] & (*data)[i]) != (*data)[i])
					{
						matched = false;
						break;
					}
				}
				if (!matched) skip = *to_skip;
				break;
			}
			case cheat_inst::copy_bytes:
			{
				auto dest_addr = parse_value_to_u32(code.value);
				auto num_bytes = parse_value_to_u32(code.opt1);
				if (!dest_addr || !num_bytes) return;
				if (!valid_range(addr, *num_bytes) || !valid_range(*dest_addr, *num_bytes)) return;
				std::memcpy(vm::get_super_ptr<u8>(addr), vm::get_super_ptr<u8>(*dest_addr), *num_bytes);
				break;
			}
			default:
				log_cheat_patch.error("Encountered invalid cheat_inst during execution!");
				return;
			}
		}
	};

	if (pause)
		cpu_thread::suspend_all(nullptr, {}, apply_cheat);
	else
		apply_cheat();

	return true;
}

// ===========================================================================
// cheat_engine implementation
// ===========================================================================
const std::set<cheat_executor>& cheat_engine::get_active_constant_cheats() const
{
	return m_constant_cheats;
}

const std::set<cheat_executor>& cheat_engine::get_queued_cheats() const
{
	return m_queued_cheats;
}

void cheat_engine::clear()
{
	std::lock_guard lock_constant(m_mutex_constant);
	std::lock_guard lock_queued(m_mutex_queued);
	m_constant_cheats.clear();
	m_queued_cheats.clear();
}

bool cheat_engine::activate_cheat(const std::string& game_name, const std::string& cheat_name,
                                  cheat_entry entry,
                                  std::unordered_map<std::string, std::string> var_choices)
{
	cheat_executor ce(game_name, cheat_name, entry, var_choices);

	if (entry.type == cheat_type::constant)
	{
		std::lock_guard lock(m_mutex_constant);
		return m_constant_cheats.insert(std::move(ce)).second;
	}

	if (Emu.IsStopped())
	{
		std::lock_guard lock(m_mutex_queued);
		return m_queued_cheats.insert(std::move(ce)).second;
	}

	return ce.execute();
}

bool cheat_engine::deactivate_cheat(const std::string& game_name, const std::string& cheat_name)
{
	{
		std::lock_guard lock(m_mutex_constant);
		for (auto it = m_constant_cheats.begin(); it != m_constant_cheats.end(); ++it)
		{
			if (it->is(game_name, cheat_name))
			{
				m_constant_cheats.erase(it);
				return true;
			}
		}
	}
	{
		std::lock_guard lock(m_mutex_queued);
		for (auto it = m_queued_cheats.begin(); it != m_queued_cheats.end(); ++it)
		{
			if (it->is(game_name, cheat_name))
			{
				m_queued_cheats.erase(it);
				return true;
			}
		}
	}
	return false;
}

void cheat_engine::apply_queued_cheats()
{
	for (const auto& cheat : m_queued_cheats)
		cheat.execute(false);
}

void cheat_engine::operator()
{
	// TODO: constant cheats background thread
}

// ===========================================================================
// cheat_storage implementation
// ===========================================================================
cheat_storage& cheat_storage::get()
{
	static cheat_storage inst;
	return inst;
}

cheat_storage::cheat_storage()
{
	load();
}

void cheat_storage::ensure_v2_loaded()
{
	if (m_v2_loaded) return;
	m_v2_loaded = true;

	const std::string patches_dir = patch_engine::get_patches_path();
	const QStringList search_paths = {
		QString::fromStdString(patches_dir) + QStringLiteral("cheatsv2.yml"),
		QCoreApplication::applicationDirPath() + QStringLiteral("/cheats/cheatsv2.yml"),
		QCoreApplication::applicationDirPath() + QStringLiteral("/cheatsv2.yml"),
	};

	for (const QString& path : search_paths)
	{
		if (QFileInfo::exists(path))
		{
			log_cheat_patch.notice("Loading cheatsv2.yml from: %s", path.toStdString());
			load_cheatsv2(path.toStdString());
			break;
		}
	}
}

bool cheat_storage::load_cheatsv2(const std::string& path)
{
	fs::file f(path, fs::read + fs::isfile);
	if (!f)
	{
		log_cheat_patch.error("Cannot open cheatsv2 file: %s", path);
		return false;
	}

	auto [root, error] = yaml_load(f.to_string());
	if (!error.empty())
	{
		log_cheat_patch.error("YAML parse error in %s: %s", path, error);
		return false;
	}

	if (!root.IsMap()) return false;

	static const std::regex serial_re("([A-Z]{4}[0-9]{5})");
	usz count = 0;

	for (const auto& game_kv : root)
	{
		const std::string game_key = game_kv.first.Scalar();
		const YAML::Node& game_node = game_kv.second;
		if (!game_node.IsMap()) continue;

		std::string serial;
		std::smatch match;
		if (std::regex_search(game_key, match, serial_re))
			serial = match[1].str();

		std::map<std::string, cheat_entry> cheats_to_add;

		for (const auto& cheat_kv : game_node)
		{
			const std::string cheat_name = cheat_kv.first.Scalar();
			const YAML::Node& cheat_node = cheat_kv.second;
			if (!cheat_node.IsMap()) continue;

			cheat_entry entry{};
			entry.game_key = game_key;
			if (!serial.empty()) entry.serials.push_back(serial);

			if (cheat_node["Author"])
				entry.author = cheat_node["Author"].Scalar();

			if (cheat_node["Comments"] && cheat_node["Comments"].IsSequence())
				for (const auto& c : cheat_node["Comments"])
					entry.comments.push_back(c.Scalar());

			if (cheat_node["Type"])
			{
				std::string type_str = cheat_node["Type"].Scalar();
				entry.type = (type_str == "Constant" || type_str == "constant") ? cheat_type::constant : cheat_type::normal;
			}

			if (cheat_node["Codes"] && cheat_node["Codes"].IsSequence())
			{
				for (const auto& code_item : cheat_node["Codes"])
				{
					if (!code_item.IsSequence() || code_item.size() < 2) continue;

					cheat_code code{};
					const std::string type_str = code_item[0].Scalar();
					code.type = v2_type_to_inst(type_str);

					// All values are stored as strings (like NCL format)
					if (code_item.size() >= 2) code.addr = code_item[1].Scalar();

					if (type_str == "find_replace" && code_item.size() >= 5)
					{
						// [find_replace, START, LENGTH, SEARCH_HEX, REPLACE_HEX]
						code.value = code_item[2].Scalar();  // length (used as end offset)
						code.opt1 = code_item[3].Scalar();  // search hex
						code.opt2 = code_item[4].Scalar();  // replace hex
						// Adjust: value should be end_addr = start + length
						std::string err;
						u32 start = get_yaml_node_value<u32>(code_item[1], err);
						u32 length = get_yaml_node_value<u32>(code_item[2], err);
						code.value = fmt::format("%X", start + length);
						code.addr = code_item[1].Scalar();
					}
					else if (type_str == "write_condensed" && code_item.size() >= 4)
					{
						// [write_condensed, ADDR, VAL1, VAL2, VAL3]
						// Store as: addr=ADDR, value=VAL1, opt1=increment, opt2=count
						code.value = code_item[2].Scalar();
						if (code_item.size() >= 4)
							code.opt1 = code_item[3].Scalar();  // We'll use this as raw data
						// For write_condensed, the NCL format expects: value=data, opt1=increment, opt2=count
						// cheatsv2 format is: [write_condensed, ADDR, VAL1, VAL2, VAL3]
						// We map it as: value=concat(VAL1,VAL2,VAL3), opt1="4", opt2="3"
						std::string combined;
						for (usz i = 2; i < code_item.size(); i++)
							combined += code_item[i].Scalar();
						code.value = combined;
						code.opt1 = "4";
						code.opt2 = fmt::format("%d", code_item.size() - 2);
					}
					else if (type_str == "read_pointer" && code_item.size() >= 3)
					{
						code.value = code_item[2].Scalar();  // offset/increment
					}
					else if (type_str == "copy_bytes" && code_item.size() >= 4)
					{
						// [copy_bytes, SRC, DST, LENGTH]
						code.value = code_item[2].Scalar();  // dest_addr
						code.opt1 = code_item[3].Scalar();  // num_bytes
					}
					else if (type_str == "copy" && code_item.size() >= 3)
					{
						code.value = code_item[2].Scalar();  // size
					}
					else if (type_str == "paste" && code_item.size() >= 3)
					{
						code.value = code_item[2].Scalar();  // size
					}
					else if (type_str == "compare_cond" || type_str == "compared_cond")
					{
						if (code_item.size() >= 4)
						{
							code.value = code_item[2].Scalar();
							code.opt1 = code_item[3].Scalar();
						}
					}
					else if (type_str == "and_compare_cond")
					{
						if (code_item.size() >= 4)
						{
							code.value = code_item[2].Scalar();
							code.opt1 = code_item[3].Scalar();
						}
					}
					else
					{
						// write_bytes, or_bytes, and_bytes, xor_bytes, write_text, write_float
						if (code_item.size() >= 3)
							code.value = code_item[2].Scalar();
					}

					entry.codes.push_back(std::move(code));
				}
			}

			if (!entry.codes.empty())
			{
				cheats_to_add.insert_or_assign(std::move(cheat_name), std::move(entry));
				count++;
			}
		}

		if (!cheats_to_add.empty())
			m_cheats.insert_or_assign(game_key, std::move(cheats_to_add));
	}

	log_cheat_patch.success("Loaded %u v2 cheat groups from %s", count, path);
	return count > 0;
}

bool cheat_storage::load_ncl(const std::string& path)
{
	auto res = ncl_parser::parse_ncl(path);
	if (!res)
	{
		log_cheat_patch.error("Failed to parse NCL file: %s", path);
		return false;
	}

	const QFileInfo file_info(QString::fromStdString(path));
	add_cheats(file_info.completeBaseName().toStdString(), std::move(*res));
	save();
	log_cheat_patch.success("Loaded NCL cheats from %s", path);
	return true;
}

bool cheat_storage::load_patch_yml(const std::string& path)
{
	fs::file f(path, fs::read + fs::isfile);
	if (!f) return false;

	auto [root, error] = yaml_load(f.to_string());
	if (!error.empty() || !root.IsMap()) return false;

	usz count = 0;
	for (const auto& kv : root)
	{
		const std::string key = kv.first.Scalar();
		if (key == "Anchors" || key == "Version") continue;
		if (!key.starts_with("PPU-") && !key.starts_with("SPU-")) continue;

		const YAML::Node& patch_map = kv.second;
		if (!patch_map.IsMap()) continue;

		std::map<std::string, cheat_entry> cheats_to_add;

		for (const auto& patch_kv : patch_map)
		{
			cheat_entry entry{};
			std::string cheat_name = patch_kv.first.Scalar();
			entry.game_key = key;

			const YAML::Node& patch_node = patch_kv.second;
			if (!patch_node.IsMap()) continue;

			if (patch_node["Author"]) entry.author = patch_node["Author"].Scalar();
			if (patch_node["Games"] && patch_node["Games"].IsMap())
			{
				for (const auto& game_kv : patch_node["Games"])
				{
					if (game_kv.second.IsMap())
						for (const auto& serial_kv : game_kv.second)
							entry.serials.push_back(serial_kv.first.Scalar());
				}
			}

			if (patch_node["Patch"] && patch_node["Patch"].IsSequence())
			{
				for (const auto& item : patch_node["Patch"])
				{
					if (!item.IsSequence() || item.size() < 2) continue;
					cheat_code code{};
					code.type = cheat_inst::write_bytes;
					code.addr = item[1].Scalar();
					if (item.size() >= 3) code.value = item[2].Scalar();
					entry.codes.push_back(std::move(code));
				}
			}

			if (!entry.codes.empty())
			{
				cheats_to_add.insert_or_assign(std::move(cheat_name), std::move(entry));
				count++;
			}
		}

		if (!cheats_to_add.empty())
			m_cheats.insert_or_assign(key, std::move(cheats_to_add));
	}

	log_cheat_patch.success("Loaded %u patch.yml cheat groups from %s", count, path);
	return count > 0;
}

void cheat_storage::save()
{
	const std::string cheats_path = patch_engine::get_patches_path();
	fs::create_path(cheats_path);
	const std::string path = cheats_path + m_cheats_filename;

	fs::file f(path, fs::rewrite);
	if (!f) return;

	YAML::Emitter out;
	out << YAML::BeginMap;

	for (const auto& [game_name, cheats] : m_cheats)
	{
		out << YAML::Key << game_name;
		out << YAML::BeginMap;

		for (const auto& [cheat_name, cheat] : cheats)
		{
			out << YAML::Key << cheat_name;
			out << YAML::BeginMap;
			out << YAML::Key << "Author" << YAML::Value << cheat.author;
			if (!cheat.comments.empty())
			{
				out << YAML::Key << "Comments" << YAML::BeginSeq;
				for (const auto& c : cheat.comments) out << c;
				out << YAML::EndSeq;
			}
			out << YAML::Key << "Type" << YAML::Value << fmt::format("%s", cheat.type);
			out << YAML::Key << "Codes" << YAML::BeginSeq;
			for (const auto& code : cheat.codes)
			{
				out << YAML::Flow << YAML::BeginSeq
					<< fmt::format("%s", code.type)
					<< code.addr << code.value << code.opt1 << code.opt2
					<< YAML::EndSeq;
			}
			out << YAML::EndSeq;
			if (!cheat.variables.empty())
			{
				out << YAML::Key << "Variables" << YAML::BeginMap;
				for (const auto& [var_name, var_options] : cheat.variables)
				{
					out << YAML::Key << var_name << YAML::BeginMap;
					for (const auto& [opt_name, opt_value] : var_options)
						out << YAML::Key << opt_name << YAML::Value << opt_value;
					out << YAML::EndMap;
				}
				out << YAML::EndMap;
			}
			out << YAML::EndMap;
		}
		out << YAML::EndMap;
	}
	out << YAML::EndMap;

	if (out.good())
		f.write(out.c_str(), out.size());
}

void cheat_storage::load()
{
	const std::string path = patch_engine::get_patches_path() + m_cheats_filename;
	fs::file f(path, fs::read + fs::isfile);
	if (!f) return;

	auto [root, error] = yaml_load(f.to_string());
	if (!error.empty() || !root.IsMap()) return;

	for (const auto& game_key : root)
	{
		const std::string game_name = game_key.first.Scalar();
		if (game_name.empty() || !game_key.second.IsMap()) continue;

		std::map<std::string, cheat_entry> cheats_to_add;

		for (const auto& cheat_key : game_key.second)
		{
			const std::string cheat_name = cheat_key.first.Scalar();
			cheat_entry cheat_data{};

			if (!cheat_key.second.IsMap()) continue;

			if (const auto author = cheat_key.second["Author"]; author && author.IsScalar())
				cheat_data.author = author.Scalar();

			if (const auto comments = cheat_key.second["Comments"]; comments && comments.IsSequence())
				for (const auto& comment : comments)
					cheat_data.comments.push_back(comment.Scalar());

			if (const auto type = cheat_key.second["Type"]; type && type.IsScalar())
			{
				std::string t = type.Scalar();
				cheat_data.type = (t == "Constant") ? cheat_type::constant : cheat_type::normal;
			}

			if (const auto codes = cheat_key.second["Codes"]; codes && codes.IsSequence())
			{
				for (const auto& code : codes)
				{
					if (!code.IsSequence() || code.size() < 5) continue;
					cheat_code ccode{};

					u64 type64;
					if (!cfg::try_to_enum_value(&type64, &fmt_class_string<cheat_inst>::format, code[0].Scalar()))
						continue;
					ccode.type = static_cast<cheat_inst>(::narrow<u8>(type64));
					ccode.addr = code[1].Scalar();
					ccode.value = code[2].Scalar();
					ccode.opt1 = code[3].Scalar();
					ccode.opt2 = code[4].Scalar();
					cheat_data.codes.push_back(std::move(ccode));
				}
			}

			if (const auto vars = cheat_key.second["Variables"]; vars && vars.IsMap())
			{
				for (const auto& var : vars)
				{
					const std::string var_name = var.first.Scalar();
					std::map<std::string, std::string> var_values;
					if (var.second.IsMap())
					{
						for (const auto& var_opt : var.second)
							var_values.insert_or_assign(var_opt.first.Scalar(), var_opt.second.Scalar());
					}
					cheat_data.variables.insert_or_assign(var_name, var_values);
				}
			}

			cheats_to_add.insert_or_assign(std::move(cheat_name), std::move(cheat_data));
		}

		add_cheats(game_name, std::move(cheats_to_add));
	}
}

void cheat_storage::add_cheats(std::string name, std::map<std::string, cheat_entry> to_add)
{
	m_cheats.insert_or_assign(std::move(name), std::move(to_add));
}

std::map<std::string, cheat_entry>* cheat_storage::cheats_for_game(const std::string& game_name)
{
	auto it = m_cheats.find(game_name);
	return (it != m_cheats.end()) ? &it->second : nullptr;
}

bool cheat_storage::has_cheats_for_serial(const std::string& serial) const
{
	for (const auto& [game_name, cheats] : m_cheats)
	{
		for (const auto& [cheat_name, entry] : cheats)
		{
			for (const auto& s : entry.serials)
			{
				if (s == serial || s == "All") return true;
			}
			// Also check if game_name contains the serial
			if (game_name.find(serial) != std::string::npos) return true;
		}
	}
	return false;
}

std::vector<std::pair<std::string, const cheat_entry*>> cheat_storage::find_by_serial(const std::string& serial) const
{
	std::vector<std::pair<std::string, const cheat_entry*>> result;

	for (const auto& [game_name, cheats] : m_cheats)
	{
		// Check if game_name contains the serial
		bool game_matches = (game_name.find(serial) != std::string::npos);

		for (const auto& [cheat_name, entry] : cheats)
		{
			if (game_matches) {
				result.emplace_back(cheat_name, &entry);
				continue;
			}
			for (const auto& s : entry.serials)
			{
				if (s == serial || s == "All")
				{
					result.emplace_back(cheat_name, &entry);
					break;
				}
			}
		}
	}
	return result;
}

// ===========================================================================
// cheat_manager_dialog implementation
// ===========================================================================
cheat_manager_dialog* cheat_manager_dialog::s_inst = nullptr;

cheat_manager_dialog::cheat_manager_dialog(QWidget* parent)
	: QDialog(parent)
{
	setWindowTitle(tr("金手指管理器"));
	setObjectName("cheat_manager_dialog");
	setMinimumSize(QSize(800, 400));

	auto* layout_main = new QVBoxLayout(this);

	// Filter group
	auto* grp_filter = new QGroupBox();
	auto* layout_grp_filter = new QHBoxLayout();
	auto* lbl_filter = new QLabel(tr("过滤:"));
	m_edt_filter = new QLineEdit();
	m_edt_filter->setClearButtonEnabled(true);
	auto* line = new QFrame();
	line->setFrameShape(QFrame::VLine);
	line->setFrameShadow(QFrame::Sunken);
	m_chk_search_cur = new QCheckBox(tr("仅搜索当前游戏"));
	layout_grp_filter->addWidget(lbl_filter);
	layout_grp_filter->addWidget(m_edt_filter);
	layout_grp_filter->addWidget(line);
	layout_grp_filter->addWidget(m_chk_search_cur);
	layout_grp_filter->addStretch();
	grp_filter->setLayout(layout_grp_filter);
	layout_main->addWidget(grp_filter);

	// Tree + info splitter
	auto* splitter = new QSplitter(Qt::Horizontal);

	m_tree = new QTreeWidget();
	m_tree->setColumnCount(1);
	m_tree->setHeaderHidden(true);

	auto* grp_views = new QGroupBox(tr("信息:"));
	auto* layout_grp_views = new QVBoxLayout();

	auto* lbl_author = new QLabel(tr("作者:"));
	m_edt_author = new QLineEdit();
	m_edt_author->setReadOnly(true);
	auto* lbl_comments = new QLabel(tr("注释:"));
	m_pte_comments = new QPlainTextEdit();
	m_pte_comments->setReadOnly(true);
	m_btn_import = new QPushButton(tr("导入 NCL 文件"));
	m_btn_import_v2 = new QPushButton(tr("导入 cheatsv2.yml"));

	layout_grp_views->addWidget(lbl_author);
	layout_grp_views->addWidget(m_edt_author);
	layout_grp_views->addWidget(lbl_comments);
	layout_grp_views->addWidget(m_pte_comments);
	layout_grp_views->addWidget(m_btn_import);
	layout_grp_views->addWidget(m_btn_import_v2);
	grp_views->setLayout(layout_grp_views);

	splitter->addWidget(m_tree);
	splitter->addWidget(grp_views);
	splitter->setStretchFactor(0, 2);
	layout_main->addWidget(splitter);

	// Connections
	connect(m_edt_filter, &QLineEdit::textChanged, this, [this](const QString& term)
	{
		if (!m_chk_search_cur->isChecked())
			filter_cheats("", term);
	});

	connect(m_chk_search_cur, &QCheckBox::stateChanged, this, [this](int state)
	{
		if (state == Qt::Checked)
		{
			QString game_id = QString::fromStdString(Emu.GetTitleID());
			QString game_title = QString::fromStdString(Emu.GetTitle());
			filter_cheats(game_id, game_title);
		}
		else
		{
			filter_cheats("", m_edt_filter->text());
		}
	});

	connect(m_btn_import, &QPushButton::clicked, this, [this](bool)
	{
		const QStringList paths = QFileDialog::getOpenFileNames(this, tr("选择要导入的 Artemis 金手指文件"),
			QString(), tr("Artemis 文件 (*.nlc *.NCL);;所有文件 (*.*)"));
		if (paths.isEmpty()) return;

		for (const auto& path : paths)
		{
			cheat_storage::get().load_ncl(path.toStdString());
		}
		refresh_tree();
	});

	connect(m_btn_import_v2, &QPushButton::clicked, this, [this](bool)
	{
		const QString path = QFileDialog::getOpenFileName(this, tr("导入 cheatsv2.yml"),
			QString(), tr("YAML 文件 (*.yml *.yaml);;所有文件 (*.*)"));
		if (path.isEmpty()) return;
		cheat_storage::get().load_cheatsv2(path.toStdString());
		refresh_tree();
	});

	connect(m_tree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int)
	{
		if (!item) return;
		const auto* parent = item->parent();
		if (!parent) return;

		const std::string game_name = parent->text(0).toStdString();
		const std::string cheat_name = item->text(0).toStdString();

		auto* cheats = cheat_storage::get().cheats_for_game(game_name);
		if (!cheats || !cheats->contains(cheat_name)) return;

		const auto& cheat = cheats->at(cheat_name);
		std::unordered_map<std::string, std::string> var_choices;
		if (!cheat.variables.empty())
		{
			cheat_variables_dialog var_dlg(QString::fromStdString(cheat_name), cheat, this);
			if (var_dlg.exec() == QDialog::Rejected) return;
			var_choices = var_dlg.get_choices();
		}

		if (!g_cheat_engine.activate_cheat(game_name, cheat_name, cheat, var_choices))
		{
			g_cheat_engine.deactivate_cheat(game_name, cheat_name);
			item->setBackground(0, QBrush());
			return;
		}

		item->setBackground(0, QBrush(QColor(100, 200, 100, 80)));
	});

	connect(m_tree, &QTreeWidget::itemClicked, this, [this](QTreeWidgetItem* item, int)
	{
		const auto* parent = item->parent();
		if (!parent) return;

		const std::string game_name = parent->text(0).toStdString();
		const std::string cheat_name = item->text(0).toStdString();

		auto* cheats = cheat_storage::get().cheats_for_game(game_name);
		if (!cheats || !cheats->contains(cheat_name)) return;

		const auto& cheat = cheats->at(cheat_name);
		m_edt_author->setText(QString::fromStdString(cheat.author));

		std::string str_comments;
		for (const auto& comment : cheat.comments)
			str_comments += comment + "\n";
		m_pte_comments->setPlainText(QString::fromStdString(str_comments));
	});

	cheat_storage::get().ensure_v2_loaded();
	refresh_tree();
}

cheat_manager_dialog::~cheat_manager_dialog()
{
	s_inst = nullptr;
}

cheat_manager_dialog* cheat_manager_dialog::get_dlg(QWidget* parent)
{
	if (!s_inst)
		s_inst = new cheat_manager_dialog(parent);
	return s_inst;
}

void cheat_manager_dialog::refresh_tree()
{
	m_tree->clear();

	QList<QTreeWidgetItem*> items;

	for (const auto& [game_name, cheats] : cheat_storage::get().all_cheats())
	{
		auto top_entry = new QTreeWidgetItem(QStringList(QString::fromStdString(game_name)));
		items.append(top_entry);

		for (const auto& [cheat_name, entry] : cheats)
		{
			auto sub_entry = new QTreeWidgetItem();
			sub_entry->setText(0, QString::fromStdString(cheat_name));
			if (entry.type == cheat_type::constant)
				sub_entry->setCheckState(0, Qt::CheckState::Unchecked);
			top_entry->addChild(sub_entry);
		}
	}

	std::sort(items.begin(), items.end(), [](QTreeWidgetItem* a, QTreeWidgetItem* b)
	{
		return a->text(0).compare(b->text(0), Qt::CaseInsensitive) < 0;
	});

	m_tree->insertTopLevelItems(0, items);

	// Highlight active/queued cheats
	const auto& constant_cheats = g_cheat_engine.get_active_constant_cheats();
	for (const auto& cheat : constant_cheats)
	{
		const auto name = cheat.get_name();
		auto found = m_tree->findItems(QString::fromStdString(name.first), Qt::MatchExactly);
		if (found.empty()) continue;

		for (int i = 0; i < found[0]->childCount(); i++)
		{
			auto* child = found[0]->child(i);
			if (child->text(0).toStdString() == name.second)
			{
				child->setCheckState(0, Qt::CheckState::Checked);
				break;
			}
		}
	}

	const auto& queued_cheats = g_cheat_engine.get_queued_cheats();
	for (const auto& cheat : queued_cheats)
	{
		const auto name = cheat.get_name();
		auto found = m_tree->findItems(QString::fromStdString(name.first), Qt::MatchExactly);
		if (found.empty()) continue;

		for (int i = 0; i < found[0]->childCount(); i++)
		{
			auto* child = found[0]->child(i);
			if (child->text(0).toStdString() == name.second)
			{
				child->setBackground(0, QBrush(QColor(100, 200, 100, 80)));
				break;
			}
		}
	}
}

void cheat_manager_dialog::filter_cheats(const QString& game_id, const QString& term)
{
	const QStringList words = term.split(" ", Qt::SkipEmptyParts);
	const auto* root = m_tree->invisibleRootItem();

	for (int i = 0; i < root->childCount(); i++)
	{
		auto* child = root->child(i);
		if (!game_id.isEmpty() && child->text(0).contains(game_id, Qt::CaseInsensitive))
		{
			child->setHidden(false);
			continue;
		}
		if (std::all_of(words.begin(), words.end(), [child](const QString& word)
		{
			return child->text(0).contains(word, Qt::CaseInsensitive);
		}))
		{
			child->setHidden(false);
			continue;
		}
		child->setHidden(true);
	}
}

// ===========================================================================
// cheat_variables_dialog implementation
// ===========================================================================
cheat_variables_dialog::cheat_variables_dialog(const QString& title, const cheat_entry& entry, QWidget* parent)
	: QDialog(parent)
{
	setWindowTitle(tr("%1 的变量").arg(title));
	setObjectName("cheat_variables_dialog");

	auto* layout_main = new QVBoxLayout(this);
	auto* gb_var = new QGroupBox(tr("变量:"));
	auto* layout_gb_var = new QVBoxLayout();

	for (const auto& [var_name, var_options] : entry.variables)
	{
		auto* layout_line = new QHBoxLayout();
		auto* label = new QLabel(QString::fromStdString(var_name));
		auto* cb = new QComboBox();

		for (const auto& [opt_name, opt_value] : var_options)
			cb->addItem(QString::fromStdString(opt_name), QString::fromStdString(opt_value));

		m_combos.push_back({var_name, cb});
		layout_line->addWidget(label);
		layout_line->addWidget(cb);
		layout_gb_var->addLayout(layout_line);
	}

	gb_var->setLayout(layout_gb_var);
	layout_main->addWidget(gb_var);

	auto* btn_box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
	connect(btn_box, &QDialogButtonBox::accepted, this, [this]()
	{
		for (const auto& [var_name, combo] : m_combos)
			m_var_choices.insert_or_assign(var_name, combo->currentData().toString().toStdString());
		accept();
	});
	connect(btn_box, &QDialogButtonBox::rejected, this, &QDialog::reject);
	layout_main->addWidget(btn_box);
}

std::unordered_map<std::string, std::string> cheat_variables_dialog::get_choices()
{
	return std::move(m_var_choices);
}

// ===========================================================================
// cheat_pre_boot_dialog implementation
// ===========================================================================
cheat_pre_boot_dialog::cheat_pre_boot_dialog(const std::string& serial, const std::string& game_name, QWidget* parent)
	: QDialog(parent)
{
	setWindowTitle(tr("金手指选择 - 游戏启动前"));
	setMinimumSize(QSize(600, 400));

	auto* layout = new QVBoxLayout(this);

	m_label = new QLabel(this);
	if (game_name.empty())
		m_label->setText(tr("游戏序列号: %1\n\n请选择要启用的金手指（双击激活），然后点击\"启动游戏\"。")
			.arg(QString::fromStdString(serial)));
	else
		m_label->setText(tr("游戏: %1\n序列号: %2\n\n请选择要启用的金手指（双击激活），然后点击\"启动游戏\"。")
			.arg(QString::fromStdString(game_name))
			.arg(QString::fromStdString(serial)));
	m_label->setWordWrap(true);
	layout->addWidget(m_label);

	// Cheat tree
	m_tree = new QTreeWidget(this);
	m_tree->setColumnCount(1);
	m_tree->setHeaderHidden(true);
	layout->addWidget(m_tree);

	// Populate with cheats for this serial
	auto cheats = cheat_storage::get().find_by_serial(serial);
	if (cheats.empty())
	{
		m_label->setText(m_label->text() + "\n\n" + tr("未找到适用于此游戏的金手指。"));
	}
	else
	{
		// Group by game key
		std::map<std::string, std::vector<std::pair<std::string, const cheat_entry*>>> grouped;
		for (const auto& [cheat_name, entry] : cheats)
		{
			std::string group_key = entry->game_key.empty() ? "Cheats" : entry->game_key;
			grouped[group_key].emplace_back(cheat_name, entry);
		}

		QList<QTreeWidgetItem*> items;
		for (const auto& [group_key, cheat_list] : grouped)
		{
			auto* top = new QTreeWidgetItem(QStringList(QString::fromStdString(group_key)));
			for (const auto& [cheat_name, entry] : cheat_list)
			{
				auto* child = new QTreeWidgetItem();
				child->setText(0, QString::fromStdString(cheat_name));
				if (entry->type == cheat_type::constant)
					child->setCheckState(0, Qt::CheckState::Unchecked);
				top->addChild(child);
			}
			items.append(top);
		}
		m_tree->insertTopLevelItems(0, items);
	}

	// Double-click to activate/deactivate
	connect(m_tree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int)
	{
		if (!item) return;
		const auto* parent = item->parent();
		if (!parent) return;

		const std::string game_name = parent->text(0).toStdString();
		const std::string cheat_name = item->text(0).toStdString();

		auto* cheats = cheat_storage::get().cheats_for_game(game_name);
		if (!cheats || !cheats->contains(cheat_name)) return;

		const auto& cheat = cheats->at(cheat_name);

		// Check if already active
		bool found = false;
		for (const auto& c : g_cheat_engine.get_active_constant_cheats())
		{
			if (c.is(game_name, cheat_name)) { found = true; break; }
		}
		for (const auto& c : g_cheat_engine.get_queued_cheats())
		{
			if (c.is(game_name, cheat_name)) { found = true; break; }
		}

		if (found)
		{
			g_cheat_engine.deactivate_cheat(game_name, cheat_name);
			item->setBackground(0, QBrush());
		}
		else
		{
			std::unordered_map<std::string, std::string> var_choices;
			if (!cheat.variables.empty())
			{
				cheat_variables_dialog var_dlg(QString::fromStdString(cheat_name), cheat, this);
				if (var_dlg.exec() == QDialog::Rejected) return;
				var_choices = var_dlg.get_choices();
			}

			if (g_cheat_engine.activate_cheat(game_name, cheat_name, cheat, var_choices))
				item->setBackground(0, QBrush(QColor(100, 200, 100, 80)));
		}
	});

	// Buttons
	auto* btn_layout = new QHBoxLayout();
	m_btn_all = new QPushButton(tr("全选"), this);
	m_btn_none = new QPushButton(tr("全不选"), this);
	btn_layout->addWidget(m_btn_all);
	btn_layout->addWidget(m_btn_none);
	btn_layout->addStretch();
	layout->addLayout(btn_layout);

	auto* bottom_layout = new QHBoxLayout();
	bottom_layout->addStretch();
	m_btn_start = new QPushButton(tr("启动游戏"), this);
	m_btn_start->setMinimumWidth(120);
	m_btn_cancel = new QPushButton(tr("取消"), this);
	m_btn_cancel->setMinimumWidth(80);
	bottom_layout->addWidget(m_btn_start);
	bottom_layout->addWidget(m_btn_cancel);
	layout->addLayout(bottom_layout);

	connect(m_btn_all, &QPushButton::clicked, this, [this]() { select_all(true); });
	connect(m_btn_none, &QPushButton::clicked, this, [this]() { select_all(false); });
	connect(m_btn_start, &QPushButton::clicked, this, [this]()
	{
		m_confirmed = true;
		accept();
	});
	connect(m_btn_cancel, &QPushButton::clicked, this, [this]()
	{
		m_confirmed = false;
		reject();
	});
}

void cheat_pre_boot_dialog::select_all(bool checked)
{
	const auto* root = m_tree->invisibleRootItem();
	for (int i = 0; i < root->childCount(); i++)
	{
		auto* top = root->child(i);
		for (int j = 0; j < top->childCount(); j++)
		{
			auto* child = top->child(j);
			if (child->flags() & Qt::ItemIsUserCheckable)
				child->setCheckState(0, checked ? Qt::Checked : Qt::Unchecked);
		}
	}
}
