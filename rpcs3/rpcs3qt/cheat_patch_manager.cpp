#include "stdafx.h"
#include "cheat_patch_manager.h"

#include "Emu/System.h"
#include "Emu/system_config.h"
#include "Emu/Memory/vm.h"
#include "Emu/CPU/CPUThread.h"
#include "Emu/IdManager.h"
#include "Emu/Cell/PPUAnalyser.h"
#include "Emu/Cell/PPUInterpreter.h"
#include "Utilities/bin_patch.h"

#include "util/yaml.hpp"
#include "util/asm.hpp"
#include "Utilities/File.h"
#include "Utilities/StrUtil.h"

#include <QHeaderView>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QMessageBox>
#include <QMenu>
#include <QFileDialog>
#include <QGroupBox>
#include <QLabel>
#include <QRegularExpression>
#include <QCoreApplication>
#include <QFileInfo>

#include <algorithm>
#include <cstring>
#include <regex>

// ===========================================================================
// Logging
// ===========================================================================
LOG_CHANNEL(log_cheat_patch);

// ===========================================================================
// Hex parsing utility
// ===========================================================================
std::vector<u8> cheat_patch_engine::parse_hex(const std::string& hex)
{
	std::vector<u8> result;
	std::string clean;
	clean.reserve(hex.size());
	for (char c : hex)
	{
		if (std::isxdigit(static_cast<unsigned char>(c)))
			clean += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	}
	if (clean.size() % 2 != 0)
		return {};
	result.reserve(clean.size() / 2);
	for (usz i = 0; i < clean.size(); i += 2)
	{
		const std::string byte_str = clean.substr(i, 2);
		result.push_back(static_cast<u8>(std::strtoul(byte_str.c_str(), nullptr, 16)));
	}
	return result;
}

// ===========================================================================
// Type helpers (patch.yml format)
// ===========================================================================
cp_patch_type cheat_patch_engine::parse_type(std::string_view text)
{
	if (text == "byte")  return cp_patch_type::byte;
	if (text == "le16")  return cp_patch_type::le16;
	if (text == "be16")  return cp_patch_type::be16;
	if (text == "le32")  return cp_patch_type::le32;
	if (text == "be32")  return cp_patch_type::be32;
	if (text == "bd32")  return cp_patch_type::be32;
	if (text == "le64")  return cp_patch_type::le64;
	if (text == "be64")  return cp_patch_type::be64;
	if (text == "bd64")  return cp_patch_type::be64;
	if (text == "lef32") return cp_patch_type::lef32;
	if (text == "bef32") return cp_patch_type::bef32;
	if (text == "lef64") return cp_patch_type::lef64;
	if (text == "bef64") return cp_patch_type::bef64;
	if (text == "utf8")  return cp_patch_type::utf8;
	if (text == "c_utf8" || text == "cutf8") return cp_patch_type::c_utf8;
	return cp_patch_type::invalid;
}

std::string cheat_patch_engine::type_name(cp_patch_type t)
{
	switch (t)
	{
	case cp_patch_type::byte:   return "byte";
	case cp_patch_type::le16:   return "le16";
	case cp_patch_type::be16:   return "be16";
	case cp_patch_type::le32:   return "le32";
	case cp_patch_type::be32:   return "be32";
	case cp_patch_type::le64:   return "le64";
	case cp_patch_type::be64:   return "be64";
	case cp_patch_type::lef32:  return "lef32";
	case cp_patch_type::bef32:  return "bef32";
	case cp_patch_type::lef64:  return "lef64";
	case cp_patch_type::bef64:  return "bef64";
	case cp_patch_type::utf8:   return "utf8";
	case cp_patch_type::c_utf8: return "c_utf8";
	default: return "invalid";
	}
}

std::string cheat_patch_engine::v2_type_name(cp_v2_type t)
{
	switch (t)
	{
	case cp_v2_type::write_bytes:     return "write_bytes";
	case cp_v2_type::find_replace:    return "find_replace";
	case cp_v2_type::write_text:      return "write_text";
	case cp_v2_type::write_float:     return "write_float";
	case cp_v2_type::read_pointer:    return "read_pointer";
	case cp_v2_type::copy_bytes:      return "copy_bytes";
	case cp_v2_type::write_condensed: return "write_condensed";
	case cp_v2_type::compared_cond:   return "compared_cond";
	default: return "unknown";
	}
}

std::string cheat_patch_engine::format_value(const cp_patch_entry& e)
{
	switch (e.type)
	{
	case cp_patch_type::lef32:
	case cp_patch_type::bef32:
		return fmt::format("%g", e.double_value);
	case cp_patch_type::lef64:
	case cp_patch_type::bef64:
		return fmt::format("%g", e.double_value);
	case cp_patch_type::utf8:
	case cp_patch_type::c_utf8:
		return e.str_value;
	default:
		return e.original_value.empty() ? fmt::format("0x%llx", e.long_value) : e.original_value;
	}
}

// ===========================================================================
// Singleton
// ===========================================================================
cheat_patch_engine& cheat_patch_engine::get()
{
	static cheat_patch_engine inst;
	return inst;
}

cheat_patch_engine::cheat_patch_engine()
{
	load_config();

	// Auto-load patch.yml files from the RPCS3 patches directory
	const std::string patches_dir = patch_engine::get_patches_path();
	if (fs::is_dir(patches_dir))
	{
		const std::vector<std::string> yml_files = {
			patches_dir + "patch.yml",
			patches_dir + "cheats_patch.yml",
		};

		for (const auto& path : yml_files)
		{
			if (fs::is_file(path))
			{
				load_patch_yml(path);
			}
		}
	}
}

// ===========================================================================
// Lazy loading of cheatsv2.yml
// ===========================================================================
static void ensure_v2_loaded(cheat_patch_engine& engine, bool& loaded)
{
	if (loaded)
		return;
	loaded = true;

	// Search for cheatsv2.yml in multiple locations
	const std::string patches_dir = patch_engine::get_patches_path();
	const QStringList search_paths = {
		QString::fromStdString(patches_dir) + QStringLiteral("cheatsv2.yml"),
		QCoreApplication::applicationDirPath() + QStringLiteral("/cheats/cheatsv2.yml"),
		QCoreApplication::applicationDirPath() + QStringLiteral("/cheatsv2.yml"),
		QString::fromStdString(patches_dir) + QStringLiteral("cheatsv2.yml"),
	};

	for (const QString& path : search_paths)
	{
		if (QFileInfo::exists(path))
		{
			log_cheat_patch.notice("Loading cheatsv2.yml from: %s", path.toStdString());
			engine.load_cheatsv2(path.toStdString());
			break;
		}
	}
}

// ===========================================================================
// patch.yml YAML parsing (existing, unchanged)
// ===========================================================================
bool cheat_patch_engine::parse_patch_seq(YAML::Node seq, cp_cheat_group& group, const YAML::Node& /*root*/)
{
	if (!seq || !seq.IsSequence())
		return false;

	for (const auto& item : seq)
	{
		if (!item.IsSequence() || item.size() < 2)
			continue;

		const auto type_str = item[0].Scalar();
		const auto type = parse_type(type_str);

		if (type == cp_patch_type::invalid)
		{
			if (type_str == "load")
			{
				if (item[1] && item[1].IsSequence())
				{
					u32 modifier = 0;
					if (item.size() >= 3)
						modifier = item[2].as<u32>(0);

					for (const auto& sub : item[1])
					{
						if (sub.IsSequence() && sub.size() >= 2)
						{
							cp_patch_entry entry{};
							entry.type = parse_type(sub[0].Scalar());
							if (entry.type == cp_patch_type::invalid)
								continue;

							std::string err;
							entry.offset = get_yaml_node_value<u32>(sub[1], err);
							if (!err.empty()) continue;
							entry.offset += modifier;
							entry.original_offset = sub[1].Scalar();

							if (entry.type != cp_patch_type::utf8 && entry.type != cp_patch_type::c_utf8 && sub.size() >= 3)
							{
								entry.original_value = sub[2].Scalar();
								if (entry.type == cp_patch_type::lef32 || entry.type == cp_patch_type::bef32)
									entry.double_value = get_yaml_node_value<f32>(sub[2], err);
								else if (entry.type == cp_patch_type::lef64 || entry.type == cp_patch_type::bef64)
									entry.double_value = get_yaml_node_value<f64>(sub[2], err);
								else
								{
									entry.long_value = get_yaml_node_value<u64>(sub[2], err);
									if (!err.empty())
										entry.long_value = get_yaml_node_value<s64>(sub[2], err);
								}
							}
							else if (sub.size() >= 3)
							{
								entry.str_value = sub[2].Scalar();
								entry.original_value = entry.str_value;
							}
							group.entries.push_back(std::move(entry));
						}
					}
				}
			}
			continue;
		}

		cp_patch_entry entry{};
		entry.type = type;

		std::string err;
		entry.offset = get_yaml_node_value<u32>(item[1], err);
		if (!err.empty())
		{
			log_cheat_patch.error("Bad offset in patch '%s': %s", group.description, err);
			continue;
		}
		entry.original_offset = item[1].Scalar();

		if (item.size() >= 3)
		{
			entry.original_value = item[2].Scalar();
			if (type == cp_patch_type::lef32 || type == cp_patch_type::bef32)
				entry.double_value = get_yaml_node_value<f32>(item[2], err);
			else if (type == cp_patch_type::lef64 || type == cp_patch_type::bef64)
				entry.double_value = get_yaml_node_value<f64>(item[2], err);
			else if (type == cp_patch_type::utf8 || type == cp_patch_type::c_utf8)
				entry.str_value = item[2].Scalar();
			else
			{
				entry.long_value = get_yaml_node_value<u64>(item[2], err);
				if (!err.empty())
				{
					err.clear();
					entry.long_value = static_cast<u64>(get_yaml_node_value<s64>(item[2], err));
				}
			}
		}
		group.entries.push_back(std::move(entry));
	}
	return true;
}

bool cheat_patch_engine::load_patch_yml(const std::string& path, std::string_view content, std::stringstream* log)
{
	std::string file_content;
	if (!content.empty())
		file_content = std::string(content);
	else
	{
		fs::file f(path, fs::read + fs::isfile);
		if (!f)
		{
			log_cheat_patch.error("Cannot open patch file: %s", path);
			return false;
		}
		file_content = f.to_string();
	}

	auto [root, error] = yaml_load(file_content);
	if (!error.empty())
	{
		log_cheat_patch.error("YAML parse error in %s: %s", path, error);
		return false;
	}

	if (!root.IsMap())
		return false;

	usz count = 0;
	for (const auto& kv : root)
	{
		const std::string key = kv.first.Scalar();
		if (key == "Anchors" || key == "Version")
			continue;
		if (!key.starts_with("PPU-") && !key.starts_with("SPU-"))
			continue;

		const YAML::Node& patch_map = kv.second;
		if (!patch_map.IsMap())
			continue;

		for (const auto& patch_kv : patch_map)
		{
			cp_cheat_group group{};
			group.description = patch_kv.first.Scalar();
			group.hash = key;
			group.is_custom = false;

			const YAML::Node& patch_node = patch_kv.second;
			if (!patch_node.IsMap())
				continue;

			if (patch_node["Author"])
				group.author = patch_node["Author"].Scalar();
			if (patch_node["Notes"])
				group.notes = patch_node["Notes"].Scalar();

			if (patch_node["Games"] && patch_node["Games"].IsMap())
			{
				for (const auto& game_kv : patch_node["Games"])
				{
					if (game_kv.second.IsMap())
					{
						for (const auto& serial_kv : game_kv.second)
							group.serials.push_back(serial_kv.first.Scalar());
					}
				}
			}

			if (patch_node["Patch"] && patch_node["Patch"].IsSequence())
				parse_patch_seq(patch_node["Patch"], group, root);

			if (!group.entries.empty())
			{
				bool found = false;
				for (auto& existing : m_cheats)
				{
					if (existing.description == group.description && existing.hash == group.hash)
					{
						for (const auto& s : group.serials)
						{
							if (std::find(existing.serials.begin(), existing.serials.end(), s) == existing.serials.end())
								existing.serials.push_back(s);
						}
						found = true;
						break;
					}
				}
				if (!found)
				{
					if (auto it = m_pending_enabled.find(group.description); it != m_pending_enabled.end())
						group.enabled = it->second;
					m_cheats.push_back(std::move(group));
					count++;
				}
			}
		}
	}

	log_cheat_patch.success("Loaded %u cheat groups from %s", count, path);
	return count > 0;
}

// ===========================================================================
// cheatsv2.yml parser (new)
// ===========================================================================
bool cheat_patch_engine::load_cheatsv2(const std::string& path, std::string_view content)
{
	std::string file_content;
	if (!content.empty())
		file_content = std::string(content);
	else
	{
		fs::file f(path, fs::read + fs::isfile);
		if (!f)
		{
			log_cheat_patch.error("Cannot open cheatsv2 file: %s", path);
			return false;
		}
		file_content = f.to_string();
	}

	auto [root, error] = yaml_load(file_content);
	if (!error.empty())
	{
		log_cheat_patch.error("YAML parse error in %s: %s", path, error);
		return false;
	}

	if (!root.IsMap())
		return false;

	// Regex to extract serial from game key (format: xxxx_SERIAL version)
	static const std::regex serial_re("([A-Z]{4}[0-9]{5})");

	usz count = 0;

	for (const auto& game_kv : root)
	{
		const std::string game_key = game_kv.first.Scalar();
		const YAML::Node& game_node = game_kv.second;
		if (!game_node.IsMap())
			continue;

		// Extract serial from game key
		std::string serial;
		std::smatch match;
		if (std::regex_search(game_key, match, serial_re))
			serial = match[1].str();

		// Iterate over cheat groups within this game
		for (const auto& cheat_kv : game_node)
		{
			const std::string cheat_name = cheat_kv.first.Scalar();
			const YAML::Node& cheat_node = cheat_kv.second;
			if (!cheat_node.IsMap())
				continue;

			cp_cheat_group group{};
			group.description = cheat_name;
			group.game_key = game_key;
			group.is_v2 = true;
			group.is_custom = false;

			if (!serial.empty())
				group.serials.push_back(serial);

			if (cheat_node["Author"])
				group.author = cheat_node["Author"].Scalar();

			if (cheat_node["Comments"] && cheat_node["Comments"].IsSequence())
			{
				for (const auto& c : cheat_node["Comments"])
					group.comments.push_back(c.Scalar());
			}

			// Parse code lines
			if (cheat_node["Codes"] && cheat_node["Codes"].IsSequence())
			{
				for (const auto& code_item : cheat_node["Codes"])
				{
					if (!code_item.IsSequence() || code_item.size() < 2)
						continue;

					cp_code_line line{};
					const std::string type_str = code_item[0].Scalar();
					line.raw = type_str;

					if (type_str == "write_bytes" || type_str == "write_condensed")
					{
						line.type = (type_str == "write_bytes") ? cp_v2_type::write_bytes : cp_v2_type::write_condensed;
						std::string err;
						line.address = get_yaml_node_value<u32>(code_item[1], err);

						if (type_str == "write_bytes")
						{
							// [write_bytes, OFFSET, HEX_DATA, "", ""]
							if (code_item.size() >= 3)
							{
								std::string hex_val = code_item[2].Scalar();
								line.data = parse_hex(hex_val);
							}
						}
						else
						{
							// [write_condensed, ADDR, VAL1, VAL2, VAL3]
							for (usz i = 2; i < code_item.size(); i++)
							{
								if (code_item[i].IsScalar())
								{
									std::string err2;
									u32 val = get_yaml_node_value<u32>(code_item[i], err2);
									line.extra.push_back(val);
								}
							}
						}
					}
					else if (type_str == "find_replace")
					{
						line.type = cp_v2_type::find_replace;
						std::string err;
						line.address = get_yaml_node_value<u32>(code_item[1], err);  // start
						if (code_item.size() >= 3)
							line.param = get_yaml_node_value<u32>(code_item[2], err);  // length
						if (code_item.size() >= 4)
							line.search = parse_hex(code_item[3].Scalar());
						if (code_item.size() >= 5)
							line.replace = parse_hex(code_item[4].Scalar());
					}
					else if (type_str == "write_text")
					{
						line.type = cp_v2_type::write_text;
						std::string err;
						line.address = get_yaml_node_value<u32>(code_item[1], err);
						if (code_item.size() >= 3)
							line.text = code_item[2].Scalar();
					}
					else if (type_str == "write_float")
					{
						line.type = cp_v2_type::write_float;
						std::string err;
						line.address = get_yaml_node_value<u32>(code_item[1], err);
						if (code_item.size() >= 3)
						{
							std::string val_str = code_item[2].Scalar();
							line.fval = std::strtod(val_str.c_str(), nullptr);
						}
					}
					else if (type_str == "read_pointer")
					{
						line.type = cp_v2_type::read_pointer;
						std::string err;
						line.address = get_yaml_node_value<u32>(code_item[1], err);
						if (code_item.size() >= 3)
							line.param = get_yaml_node_value<u32>(code_item[2], err);
					}
					else if (type_str == "copy_bytes")
					{
						line.type = cp_v2_type::copy_bytes;
						std::string err;
						line.address = get_yaml_node_value<u32>(code_item[1], err);  // src
						if (code_item.size() >= 3)
							line.dst_address = get_yaml_node_value<u32>(code_item[2], err);  // dst
						if (code_item.size() >= 4)
							line.param = get_yaml_node_value<u32>(code_item[3], err);  // length
					}
					else if (type_str == "compared_cond")
					{
						line.type = cp_v2_type::compared_cond;
						std::string err;
						line.address = get_yaml_node_value<u32>(code_item[1], err);
						if (code_item.size() >= 3)
						{
							// Value could be hex string or number
							std::string val_str = code_item[2].Scalar();
							line.data = parse_hex(val_str);
							if (line.data.empty())
							{
								line.param = get_yaml_node_value<u32>(code_item[2], err);
							}
						}
						if (code_item.size() >= 4)
						{
							std::string err2;
							u32 len = get_yaml_node_value<u32>(code_item[3], err2);
							line.dst_address = len;
						}
					}
					else
					{
						line.type = cp_v2_type::unknown;
						line.raw = type_str;
					}

					group.codes.push_back(std::move(line));
				}
			}

			if (!group.codes.empty())
			{
				// Restore enabled state from config
				std::string config_key = group.game_key + "|" + group.description;
				if (auto it = m_pending_enabled.find(config_key); it != m_pending_enabled.end())
					group.enabled = it->second;
				else if (auto it2 = m_pending_enabled.find(group.description); it2 != m_pending_enabled.end())
					group.enabled = it2->second;

				m_cheats.push_back(std::move(group));
				count++;
			}
		}
	}

	m_v2_loaded = true;
	log_cheat_patch.success("Loaded %u v2 cheat groups from %s", count, path);
	return count > 0;
}

// ===========================================================================
// Memory writing — raw bytes
// ===========================================================================
bool cheat_patch_engine::write_raw_bytes(u32 addr, const u8* data, u32 size)
{
	if (size == 0 || !data)
		return false;

	if (!vm::check_addr(addr, vm::page_writable, size))
		return false;

	return cpu_thread::suspend_all(nullptr, {}, [&]()
	{
		if (!vm::check_addr(addr, vm::page_writable, size))
			return false;

		u8* ptr = vm::get_super_ptr<u8>(addr);
		std::memcpy(ptr, data, size);

		// Flush instruction cache if executable
		const bool exec = vm::check_addr(addr, vm::page_executable) ||
		                 (size > 1 && vm::check_addr(addr + size - 1, vm::page_executable));
		if (exec)
		{
			extern void ppu_register_function_at(u32, u32, ppu_intrp_func_t);
			u32 ea = addr & -4;
			u32 sz = utils::align<u32>(addr + size, 4) - ea;
			ppu_register_function_at(ea, sz, nullptr);
		}
		return true;
	});
}

// ===========================================================================
// Memory writing — find and replace bytes
// ===========================================================================
bool cheat_patch_engine::find_replace_bytes(u32 start, u32 length,
                                             const u8* search, u32 search_len,
                                             const u8* replace, u32 replace_len)
{
	if (search_len == 0 || length < search_len)
		return false;

	// Clamp search range to valid memory
	u32 search_end = start + length;
	if (search_end < start)  // overflow
		search_end = 0xFFFFFFFF;

	bool found = false;

	// Search through memory page by page
	for (u32 addr = start; addr + search_len <= search_end; addr++)
	{
		if (!vm::check_addr(addr, vm::page_readable, search_len))
			continue;

		const u8* ptr = vm::get_super_ptr<u8>(addr);
		if (!ptr)
			continue;

		if (std::memcmp(ptr, search, search_len) == 0)
		{
			// Found the pattern — replace it
			u32 write_len = std::min(search_len, replace_len);
			if (vm::check_addr(addr, vm::page_writable, write_len))
			{
				u8* wptr = vm::get_super_ptr<u8>(addr);
				cpu_thread::suspend_all(nullptr, {}, [&]()
				{
					std::memcpy(wptr, replace, write_len);

					// Flush instruction cache if executable
					if (vm::check_addr(addr, vm::page_executable))
					{
						extern void ppu_register_function_at(u32, u32, ppu_intrp_func_t);
						u32 ea = addr & -4;
						u32 sz = utils::align<u32>(addr + write_len, 4) - ea;
						ppu_register_function_at(ea, sz, nullptr);
					}
				});

				log_cheat_patch.notice("find_replace: replaced %u bytes at 0x%x", write_len, addr);
				found = true;
			}
			break;  // Only replace first occurrence
		}
	}

	if (!found)
		log_cheat_patch.warning("find_replace: pattern not found in range 0x%x-0x%x", start, search_end);

	return found;
}

// ===========================================================================
// Apply a single v2 code line
// ===========================================================================
bool cheat_patch_engine::apply_v2_code(const cp_code_line& code)
{
	switch (code.type)
	{
	case cp_v2_type::write_bytes:
		if (!code.data.empty())
			return write_raw_bytes(code.address, code.data.data(), static_cast<u32>(code.data.size()));
		return false;

	case cp_v2_type::find_replace:
		if (!code.search.empty() && !code.replace.empty())
			return find_replace_bytes(code.address, code.param,
			                          code.search.data(), static_cast<u32>(code.search.size()),
			                          code.replace.data(), static_cast<u32>(code.replace.size()));
		return false;

	case cp_v2_type::write_text:
	{
		std::vector<u8> text_data(code.text.begin(), code.text.end());
		text_data.push_back(0);  // null-terminate
		return write_raw_bytes(code.address, text_data.data(), static_cast<u32>(text_data.size()));
	}

	case cp_v2_type::write_float:
	{
		be_t<f32> val = static_cast<f32>(code.fval);
		return write_raw_bytes(code.address, reinterpret_cast<const u8*>(&val), sizeof(val));
	}

	case cp_v2_type::copy_bytes:
	{
		if (code.param == 0)
			return false;
		if (!vm::check_addr(code.address, vm::page_readable, code.param))
			return false;
		if (!vm::check_addr(code.dst_address, vm::page_writable, code.param))
			return false;
		const u8* src = vm::get_super_ptr<u8>(code.address);
		return write_raw_bytes(code.dst_address, src, code.param);
	}

	case cp_v2_type::write_condensed:
	{
		// Write each extra value as a 32-bit big-endian value at sequential addresses
		bool any = false;
		u32 addr = code.address;
		for (u32 val : code.extra)
		{
			be_t<u32> be_val = val;
			if (write_raw_bytes(addr, reinterpret_cast<const u8*>(&be_val), sizeof(be_val)))
				any = true;
			addr += 4;
		}
		return any;
	}

	case cp_v2_type::compared_cond:
	{
		// Conditional write: compare value at address, write if different
		if (code.data.empty())
		{
			// Use param as value
			be_t<u32> val = code.param;
			return write_raw_bytes(code.address, reinterpret_cast<const u8*>(&val), sizeof(val));
		}
		return write_raw_bytes(code.address, code.data.data(), static_cast<u32>(code.data.size()));
	}

	case cp_v2_type::read_pointer:
		// Pointer resolution not yet fully implemented
		log_cheat_patch.notice("read_pointer: base=0x%x offset=0x%x (not yet implemented)", code.address, code.param);
		return false;

	default:
		return false;
	}
}

// ===========================================================================
// Memory writing — patch.yml entry (existing)
// ===========================================================================
bool cheat_patch_engine::write_entry(u32 addr, const cp_patch_entry& entry)
{
	const u32 size = cp_type_size(entry.type);
	if (size == 0 && entry.type != cp_patch_type::utf8 && entry.type != cp_patch_type::c_utf8)
		return false;

	u32 write_size = size;
	if (entry.type == cp_patch_type::utf8)
		write_size = ::size32(entry.str_value);
	else if (entry.type == cp_patch_type::c_utf8)
		write_size = ::size32(entry.str_value) + 1;

	if (write_size == 0)
		return false;

	if (!vm::check_addr(addr, vm::page_writable, write_size))
		return false;

	return cpu_thread::suspend_all(nullptr, {}, [&]()
	{
		if (!vm::check_addr(addr, vm::page_writable, write_size))
			return false;

		u8* ptr = vm::get_super_ptr<u8>(addr);

		switch (entry.type)
		{
		case cp_patch_type::byte:
			*ptr = static_cast<u8>(entry.long_value);
			break;
		case cp_patch_type::le16:
		{
			le_t<u16> v = static_cast<u16>(entry.long_value);
			std::memcpy(ptr, &v, sizeof(v));
			break;
		}
		case cp_patch_type::be16:
		{
			be_t<u16> v = static_cast<u16>(entry.long_value);
			std::memcpy(ptr, &v, sizeof(v));
			break;
		}
		case cp_patch_type::le32:
		{
			le_t<u32> v = static_cast<u32>(entry.long_value);
			std::memcpy(ptr, &v, sizeof(v));
			break;
		}
		case cp_patch_type::be32:
		{
			be_t<u32> v = static_cast<u32>(entry.long_value);
			std::memcpy(ptr, &v, sizeof(v));
			break;
		}
		case cp_patch_type::le64:
		{
			le_t<u64> v = entry.long_value;
			std::memcpy(ptr, &v, sizeof(v));
			break;
		}
		case cp_patch_type::be64:
		{
			be_t<u64> v = entry.long_value;
			std::memcpy(ptr, &v, sizeof(v));
			break;
		}
		case cp_patch_type::lef32:
		{
			le_t<f32> v = static_cast<f32>(entry.double_value);
			std::memcpy(ptr, &v, sizeof(v));
			break;
		}
		case cp_patch_type::bef32:
		{
			be_t<f32> v = static_cast<f32>(entry.double_value);
			std::memcpy(ptr, &v, sizeof(v));
			break;
		}
		case cp_patch_type::lef64:
		{
			le_t<f64> v = entry.double_value;
			std::memcpy(ptr, &v, sizeof(v));
			break;
		}
		case cp_patch_type::bef64:
		{
			be_t<f64> v = entry.double_value;
			std::memcpy(ptr, &v, sizeof(v));
			break;
		}
		case cp_patch_type::utf8:
			std::memcpy(ptr, entry.str_value.data(), entry.str_value.size());
			break;
		case cp_patch_type::c_utf8:
			std::memcpy(ptr, entry.str_value.data(), entry.str_value.size());
			ptr[entry.str_value.size()] = '\0';
			break;
		default:
			return false;
		}

		const bool exec_start = vm::check_addr(addr, vm::page_executable);
		const bool exec_end = (write_size <= 1) ? exec_start : vm::check_addr(addr + write_size - 1, vm::page_executable);
		if (exec_start || exec_end)
		{
			extern void ppu_register_function_at(u32, u32, ppu_intrp_func_t);
			u32 ea = addr, sz = write_size;
			if (exec_start && exec_end)
			{
				sz = utils::align<u32>(ea + sz, 4) - (ea & -4);
				ea &= -4;
			}
			else if (exec_start)
			{
				sz = utils::align<u32>(4096 - (ea & 4095), 4);
				ea &= -4;
			}
			else
			{
				sz -= utils::align<u32>(sz - 4096 + (ea & 4095), 4);
				ea = utils::align<u32>(ea, 4096);
			}
			ppu_register_function_at(ea, sz, nullptr);
		}
		return true;
	});
}

// ===========================================================================
// Apply a single cheat group
// ===========================================================================
bool cheat_patch_engine::apply_group(const cp_cheat_group& group)
{
	if (Emu.IsStopped())
		return false;

	bool any = false;

	if (group.is_v2)
	{
		for (const auto& code : group.codes)
		{
			if (apply_v2_code(code))
				any = true;
			else
				log_cheat_patch.error("Failed to apply v2 code '%s' (%s) at 0x%x",
					group.description, v2_type_name(code.type), code.address);
		}
	}
	else
	{
		for (const auto& entry : group.entries)
		{
			if (write_entry(entry.offset, entry))
				any = true;
			else
				log_cheat_patch.error("Failed to write cheat '%s' at 0x%x (%s)",
					group.description, entry.offset, type_name(entry.type));
		}
	}

	return any;
}

// ===========================================================================
// Apply all enabled cheats for the current game
// ===========================================================================
void cheat_patch_engine::apply_cheats()
{
	if (Emu.IsStopped())
		return;

	// Lazy load cheatsv2.yml if needed
	ensure_v2_loaded(*this, m_v2_loaded);

	const std::string serial = Emu.GetTitleID();
	if (serial.empty())
		return;

	for (auto& group : m_cheats)
	{
		if (!group.enabled)
			continue;

		// Check if this cheat matches the current game
		bool matches = group.serials.empty();
		for (const auto& s : group.serials)
		{
			if (s == serial || s == "All")
			{
				matches = true;
				break;
			}
		}
		if (!matches)
			continue;

		// For one-shot codes (find_replace, etc.), skip if already applied
		if (group.applied)
		{
			// Only re-apply write_bytes type codes (freeze effect)
			if (group.is_v2)
			{
				bool has_write_bytes = false;
				for (const auto& code : group.codes)
				{
					if (code.type == cp_v2_type::write_bytes)
					{
						has_write_bytes = true;
						break;
					}
				}
				if (!has_write_bytes)
					continue;
			}
			else
				continue;  // patch.yml cheats don't need re-application
		}

		apply_group(group);
		group.applied = true;
	}
}

// ===========================================================================
// Custom cheat management
// ===========================================================================
void cheat_patch_engine::add_custom_cheat(const std::string& name, const std::string& serial,
                                           cp_patch_type type, u32 offset, u64 value,
                                           const std::string& str_value)
{
	cp_cheat_group group{};
	group.description = name;
	group.is_custom = true;
	group.hash = "CUSTOM";
	if (!serial.empty())
		group.serials.push_back(serial);

	cp_patch_entry entry{};
	entry.type = type;
	entry.offset = offset;
	entry.long_value = value;
	entry.str_value = str_value;
	entry.original_offset = fmt::format("0x%x", offset);
	entry.original_value = str_value.empty() ? fmt::format("0x%llx", value) : str_value;
	group.entries.push_back(std::move(entry));

	m_cheats.push_back(std::move(group));
	save_config();
}

bool cheat_patch_engine::remove_cheat(const std::string& description)
{
	for (auto it = m_cheats.begin(); it != m_cheats.end(); ++it)
	{
		if (it->description == description && it->is_custom)
		{
			m_cheats.erase(it);
			save_config();
			return true;
		}
	}
	return false;
}

void cheat_patch_engine::set_enabled(const std::string& description, bool enabled)
{
	for (auto& g : m_cheats)
	{
		if (g.description == description)
		{
			g.enabled = enabled;
			g.applied = false;  // Reset applied state when toggling
			save_config();
			return;
		}
	}
}

// ===========================================================================
// Config persistence
// ===========================================================================
void cheat_patch_engine::save_config()
{
	const std::string dir = fs::get_config_dir() + "cheats/";
	fs::create_path(dir);

	const std::string path = dir + m_config_file;
	fs::file f(path, fs::rewrite);
	if (!f)
		return;

	YAML::Emitter out;
	out << YAML::BeginMap;
	out << YAML::Key << "Cheats" << YAML::Value << YAML::BeginSeq;

	for (const auto& g : m_cheats)
	{
		out << YAML::BeginMap;
		out << YAML::Key << "Description" << YAML::Value << g.description;
		out << YAML::Key << "Hash" << YAML::Value << g.hash;
		out << YAML::Key << "Enabled" << YAML::Value << g.enabled;
		out << YAML::Key << "Custom" << YAML::Value << g.is_custom;
		if (g.is_v2)
			out << YAML::Key << "IsV2" << YAML::Value << g.is_v2;
		if (!g.game_key.empty())
			out << YAML::Key << "GameKey" << YAML::Value << g.game_key;
		if (!g.serials.empty())
		{
			out << YAML::Key << "Serials" << YAML::Value << YAML::Flow << YAML::BeginSeq;
			for (const auto& s : g.serials)
				out << s;
			out << YAML::EndSeq;
		}
		if (g.is_custom && !g.entries.empty())
		{
			const auto& e = g.entries[0];
			out << YAML::Key << "Type" << YAML::Value << type_name(e.type);
			out << YAML::Key << "Offset" << YAML::Value << e.original_offset;
			out << YAML::Key << "Value" << YAML::Value << e.original_value;
		}
		out << YAML::EndMap;
	}

	out << YAML::EndSeq << YAML::EndMap;
	f.write(out.c_str(), out.size());
}

void cheat_patch_engine::load_config()
{
	const std::string path = fs::get_config_dir() + "cheats/" + m_config_file;
	fs::file f(path, fs::read + fs::isfile);
	if (!f)
		return;

	auto [root, err] = yaml_load(f.to_string());
	if (!err.empty() || !root.IsMap())
		return;

	if (!root["Cheats"] || !root["Cheats"].IsSequence())
		return;

	for (const auto& node : root["Cheats"])
	{
		if (!node.IsMap())
			continue;

		const std::string desc = node["Description"] ? node["Description"].Scalar() : "";
		const std::string hash = node["Hash"] ? node["Hash"].Scalar() : "";
		const bool enabled = node["Enabled"] && node["Enabled"].as<bool>(false);
		const bool custom = node["Custom"] && node["Custom"].as<bool>(false);

		if (custom)
		{
			cp_cheat_group g{};
			g.description = desc;
			g.hash = hash;
			g.enabled = enabled;
			g.is_custom = true;

			if (node["Serials"] && node["Serials"].IsSequence())
			{
				for (const auto& s : node["Serials"])
					g.serials.push_back(s.Scalar());
			}

			if (node["Type"] && node["Offset"])
			{
				cp_patch_entry e{};
				e.type = parse_type(node["Type"].Scalar());
				std::string e2;
				e.offset = get_yaml_node_value<u32>(node["Offset"], e2);
				e.original_offset = node["Offset"].Scalar();

				if (node["Value"])
				{
					e.original_value = node["Value"].Scalar();
					if (e.type == cp_patch_type::lef32 || e.type == cp_patch_type::bef32)
						e.double_value = get_yaml_node_value<f32>(node["Value"], e2);
					else if (e.type == cp_patch_type::lef64 || e.type == cp_patch_type::bef64)
						e.double_value = get_yaml_node_value<f64>(node["Value"], e2);
					else if (e.type == cp_patch_type::utf8 || e.type == cp_patch_type::c_utf8)
						e.str_value = node["Value"].Scalar();
					else
						e.long_value = get_yaml_node_value<u64>(node["Value"], e2);
				}
				g.entries.push_back(std::move(e));
			}

			if (!g.entries.empty())
				m_cheats.push_back(std::move(g));
		}
		else
		{
			// For non-custom cheats, store enabled state to apply when loaded
			std::string key = desc;
			if (node["GameKey"])
				key = node["GameKey"].Scalar() + "|" + desc;
			m_pending_enabled[key] = enabled;
			m_pending_enabled[desc] = enabled;  // Also store by description only
		}
	}
}

// ===========================================================================
// Lookups
// ===========================================================================
std::vector<cp_cheat_group*> cheat_patch_engine::cheats_for_serial(const std::string& serial)
{
	// Lazy load cheatsv2.yml
	ensure_v2_loaded(*this, m_v2_loaded);

	std::vector<cp_cheat_group*> result;
	for (auto& g : m_cheats)
	{
		if (g.serials.empty())
		{
			result.push_back(&g);
			continue;
		}
		for (const auto& s : g.serials)
		{
			if (s == serial || s == "All")
			{
				result.push_back(&g);
				break;
			}
		}
	}
	return result;
}

cp_cheat_group* cheat_patch_engine::find(const std::string& description)
{
	for (auto& g : m_cheats)
	{
		if (g.description == description)
			return &g;
	}
	return nullptr;
}

bool cheat_patch_engine::has_cheats_for_serial(const std::string& serial) const
{
	for (const auto& g : m_cheats)
	{
		if (g.serials.empty())
			return true;
		for (const auto& s : g.serials)
		{
			if (s == serial || s == "All")
				return true;
		}
	}
	return false;
}

// ===========================================================================
// Main cheat manager dialog
// ===========================================================================
cheat_patch_dialog* cheat_patch_dialog::s_inst = nullptr;

cheat_patch_dialog::cheat_patch_dialog(QWidget* parent)
	: QDialog(parent)
	, m_engine(cheat_patch_engine::get())
{
	setWindowTitle(tr("金手指管理器"));
	setObjectName("cheat_patch_dialog");
	setMinimumSize(QSize(900, 500));

	auto* layout = new QVBoxLayout(this);

	// Toolbar
	auto* toolbar = new QHBoxLayout();
	m_btn_import = new QPushButton(tr("导入 patch.yml"), this);
	m_btn_import_v2 = new QPushButton(tr("导入 cheatsv2.yml"), this);
	m_btn_add    = new QPushButton(tr("添加自定义金手指"), this);
	m_btn_apply  = new QPushButton(tr("立即应用"), this);
	m_chk_auto   = new QCheckBox(tr("自动应用"), this);
	m_chk_auto->setToolTip(tr("勾选后，所有启用的金手指将在游戏运行时持续重新写入内存。"));
	m_chk_auto->setChecked(g_cfg.misc.cheat_patch_auto_apply.get());

	toolbar->addWidget(m_btn_import);
	toolbar->addWidget(m_btn_import_v2);
	toolbar->addWidget(m_btn_add);
	toolbar->addStretch();
	toolbar->addWidget(m_chk_auto);
	toolbar->addWidget(m_btn_apply);
	layout->addLayout(toolbar);

	// Cheat table
	m_table = new QTableWidget(this);
	m_table->setColumnCount(7);
	m_table->setHorizontalHeaderLabels(QStringList()
		<< tr("启用") << tr("描述") << tr("作者")
		<< tr("类型") << tr("地址") << tr("值") << tr("序列号"));
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_table->setContextMenuPolicy(Qt::CustomContextMenu);
	m_table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(m_table);

	// Connections
	connect(m_btn_import, &QPushButton::clicked, this, &cheat_patch_dialog::on_import);
	connect(m_btn_import_v2, &QPushButton::clicked, this, &cheat_patch_dialog::on_import_v2);
	connect(m_btn_add, &QPushButton::clicked, this, &cheat_patch_dialog::on_add_custom);
	connect(m_btn_apply, &QPushButton::clicked, this, &cheat_patch_dialog::on_apply_now);
	connect(m_table, &QTableWidget::itemChanged, this, &cheat_patch_dialog::on_item_changed);
	connect(m_table, &QTableWidget::customContextMenuRequested, this, &cheat_patch_dialog::on_context_menu);

	connect(m_chk_auto, &QCheckBox::stateChanged, this, [](int state)
	{
		const bool on = state == Qt::Checked;
		g_cfg.misc.cheat_patch_auto_apply.set(on);
		Emulator::SaveSettings(g_cfg.to_string(), "");
		log_cheat_patch.success("Cheat patch auto-apply %s", on ? "enabled" : "disabled");
	});

	refresh_list();
}

cheat_patch_dialog::~cheat_patch_dialog()
{
	s_inst = nullptr;
}

cheat_patch_dialog* cheat_patch_dialog::get_dlg(QWidget* parent)
{
	if (!s_inst)
		s_inst = new cheat_patch_dialog(parent);
	return s_inst;
}

void cheat_patch_dialog::refresh_list()
{
	const QSignalBlocker blocker(m_table);
	m_table->setRowCount(0);

	const std::string serial = Emu.GetTitleID();
	auto cheats = m_engine.cheats_for_serial(serial);

	m_table->setRowCount(static_cast<int>(cheats.size()));

	int row = 0;
	for (const auto* g : cheats)
	{
		auto* chk = new QTableWidgetItem();
		chk->setFlags((chk->flags() | Qt::ItemIsUserCheckable) & ~Qt::ItemIsEditable);
		chk->setCheckState(g->enabled ? Qt::Checked : Qt::Unchecked);
		m_table->setItem(row, 0, chk);

		m_table->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(g->description)));
		m_table->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(g->author)));

		if (g->is_v2)
		{
			// Show v2 code info
			if (g->codes.size() == 1)
			{
				const auto& c = g->codes[0];
				m_table->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(cheat_patch_engine::v2_type_name(c.type))));
				m_table->setItem(row, 4, new QTableWidgetItem(QString("0x%1").arg(c.address, 8, 16, QChar('0'))));
				if (!c.data.empty())
				{
					QString hex;
					for (u8 b : c.data)
						hex += QString("%1").arg(b, 2, 16, QChar('0')).toUpper();
					m_table->setItem(row, 5, new QTableWidgetItem(hex));
				}
				else if (!c.text.empty())
					m_table->setItem(row, 5, new QTableWidgetItem(QString::fromStdString(c.text)));
				else
					m_table->setItem(row, 5, new QTableWidgetItem(""));
			}
			else
			{
				m_table->setItem(row, 3, new QTableWidgetItem(tr("%1 条代码").arg(g->codes.size())));
				m_table->setItem(row, 4, new QTableWidgetItem(""));
				m_table->setItem(row, 5, new QTableWidgetItem(""));
			}
		}
		else
		{
			if (g->entries.size() == 1)
			{
				const auto& e = g->entries[0];
				m_table->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(cheat_patch_engine::type_name(e.type))));
				m_table->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(e.original_offset)));
				m_table->setItem(row, 5, new QTableWidgetItem(QString::fromStdString(cheat_patch_engine::format_value(e))));
			}
			else
			{
				m_table->setItem(row, 3, new QTableWidgetItem(tr("%1 条目").arg(g->entries.size())));
				m_table->setItem(row, 4, new QTableWidgetItem(""));
				m_table->setItem(row, 5, new QTableWidgetItem(""));
			}
		}

		QStringList sl;
		for (const auto& s : g->serials)
			sl << QString::fromStdString(s);
		m_table->setItem(row, 6, new QTableWidgetItem(sl.join(", ")));

		chk->setData(Qt::UserRole, QString::fromStdString(g->description));

		if (g->is_custom)
		{
			for (int c = 0; c < m_table->columnCount(); c++)
			{
				if (auto* item = m_table->item(row, c))
					item->setBackground(QColor(255, 255, 200));
			}
		}

		row++;
	}

	m_table->resizeColumnsToContents();
	m_table->horizontalHeader()->setStretchLastSection(true);
}

void cheat_patch_dialog::on_import()
{
	const QString path = QFileDialog::getOpenFileName(this, tr("导入 patch.yml"), QString(), tr("YAML 文件 (*.yml *.yaml);;所有文件 (*)"));
	if (path.isEmpty())
		return;

	std::stringstream log;
	if (m_engine.load_patch_yml(path.toStdString(), "", &log))
	{
		QMessageBox::information(this, tr("导入"), tr("金手指导入成功。"));
		refresh_list();
	}
	else
	{
		QMessageBox::warning(this, tr("导入"), tr("导入失败，请查看日志了解详情。"));
	}
}

void cheat_patch_dialog::on_import_v2()
{
	const QString path = QFileDialog::getOpenFileName(this, tr("导入 cheatsv2.yml"), QString(), tr("YAML 文件 (*.yml *.yaml);;所有文件 (*)"));
	if (path.isEmpty())
		return;

	if (m_engine.load_cheatsv2(path.toStdString()))
	{
		QMessageBox::information(this, tr("导入"), tr("cheatsv2.yml 导入成功。"));
		refresh_list();
	}
	else
	{
		QMessageBox::warning(this, tr("导入"), tr("导入失败，请查看日志了解详情。"));
	}
}

void cheat_patch_dialog::on_add_custom()
{
	cp_add_cheat_dialog dlg(this);
	if (dlg.exec() != QDialog::Accepted)
		return;

	const QString name = dlg.name();
	const QString serial = dlg.serial();
	const cp_patch_type type = dlg.patch_type();
	const u32 offset = dlg.offset();
	const u64 value = dlg.value();
	const QString str = dlg.str_value();

	if (name.isEmpty())
	{
		QMessageBox::warning(this, tr("添加金手指"), tr("名称不能为空。"));
		return;
	}

	m_engine.add_custom_cheat(name.toStdString(), serial.toStdString(),
	                          type, offset, value, str.toStdString());
	refresh_list();
}

void cheat_patch_dialog::on_apply_now()
{
	if (Emu.IsStopped())
	{
		QMessageBox::information(this, tr("应用"), tr("没有游戏正在运行。"));
		return;
	}

	int applied = 0;
	for (const auto& g : m_engine.all_cheats())
	{
		if (g.enabled)
		{
			if (m_engine.apply_group(g))
				applied++;
		}
	}

	QMessageBox::information(this, tr("应用"), tr("已应用 %n 个金手指组。", "", applied));
}

void cheat_patch_dialog::on_item_changed(QTableWidgetItem* item)
{
	if (!item || item->column() != 0)
		return;

	const QString desc = item->data(Qt::UserRole).toString();
	const bool enabled = item->checkState() == Qt::Checked;
	m_engine.set_enabled(desc.toStdString(), enabled);
}

void cheat_patch_dialog::on_context_menu(const QPoint& pos)
{
	auto* item = m_table->itemAt(pos);
	if (!item)
		return;

	int row = m_table->row(item);
	auto* desc_item = m_table->item(row, 1);
	if (!desc_item)
		return;

	const std::string desc = desc_item->text().toStdString();
	cp_cheat_group* g = m_engine.find(desc);

	QMenu menu(this);

	if (g && g->is_custom)
	{
		auto* action_del = menu.addAction(tr("删除自定义金手指"));
		connect(action_del, &QAction::triggered, this, [this, desc]()
		{
			if (m_engine.remove_cheat(desc))
				refresh_list();
		});
	}

	if (g && !g->comments.empty())
	{
		auto* action_detail = menu.addAction(tr("查看详情"));
		connect(action_detail, &QAction::triggered, this, [this, g]()
		{
			QString html = QString("<h3>%1</h3>").arg(QString::fromStdString(g->description));
			html += QString("<p><b>作者:</b> %1<br>").arg(QString::fromStdString(g->author));
			if (g->is_v2)
				html += QString("<b>游戏:</b> %1<br>").arg(QString::fromStdString(g->game_key));
			else
				html += QString("<b>哈希:</b> %1<br>").arg(QString::fromStdString(g->hash));
			if (!g->comments.empty())
			{
				html += "<b>注释:</b><br>";
				for (const auto& c : g->comments)
					html += QString::fromStdString(c) + "<br>";
			}
			html += "</p>";

			if (g->is_v2)
			{
				html += "<table border='1' cellpadding='4'><tr><th>类型</th><th>地址</th><th>数据</th></tr>";
				for (const auto& c : g->codes)
				{
					QString data_str;
					if (!c.data.empty())
					{
						for (u8 b : c.data)
							data_str += QString("%1").arg(b, 2, 16, QChar('0')).toUpper();
					}
					else if (!c.text.empty())
						data_str = QString::fromStdString(c.text);
					else
						data_str = QString::number(c.fval);

					html += QString("<tr><td>%1</td><td>0x%2</td><td>%3</td></tr>")
						.arg(QString::fromStdString(cheat_patch_engine::v2_type_name(c.type)))
						.arg(c.address, 8, 16, QChar('0'))
						.arg(data_str);
				}
				html += "</table>";
			}
			else
			{
				html += "<table border='1' cellpadding='4'><tr><th>类型</th><th>偏移</th><th>值</th></tr>";
				for (const auto& e : g->entries)
				{
					html += QString("<tr><td>%1</td><td>%2</td><td>%3</td></tr>")
						.arg(QString::fromStdString(cheat_patch_engine::type_name(e.type)))
						.arg(QString::fromStdString(e.original_offset))
						.arg(QString::fromStdString(cheat_patch_engine::format_value(e)));
				}
				html += "</table>";
			}

			QMessageBox::information(this, tr("金手指详情"), html);
		});
	}

	if (!menu.isEmpty())
		menu.exec(m_table->viewport()->mapToGlobal(pos));
}

// ===========================================================================
// Pre-game-boot cheat selection dialog
// ===========================================================================
cheat_pre_boot_dialog::cheat_pre_boot_dialog(const std::string& serial, const std::string& game_name, QWidget* parent)
	: QDialog(parent)
	, m_engine(cheat_patch_engine::get())
	, m_serial(serial)
{
	setWindowTitle(tr("金手指选择 - 游戏启动前"));
	setMinimumSize(QSize(600, 400));

	auto* layout = new QVBoxLayout(this);

	// Title label
	m_label = new QLabel(this);
	if (game_name.empty())
		m_label->setText(tr("游戏序列号: %1\n\n请选择要启用的金手指，然后点击\"启动游戏\"。")
			.arg(QString::fromStdString(serial)));
	else
		m_label->setText(tr("游戏: %1\n序列号: %2\n\n请选择要启用的金手指，然后点击\"启动游戏\"。")
			.arg(QString::fromStdString(game_name))
			.arg(QString::fromStdString(serial)));
	m_label->setWordWrap(true);
	layout->addWidget(m_label);

	// Cheat list
	m_list = new QListWidget(this);
	m_list->setSelectionMode(QAbstractItemView::NoSelection);
	layout->addWidget(m_list);

	// Populate list with cheats for this serial
	auto cheats = m_engine.cheats_for_serial(serial);
	int available = 0;
	for (const auto* g : cheats)
	{
		// Skip custom cheats with different serial
		if (!g->serials.empty())
		{
			bool match = false;
			for (const auto& s : g->serials)
			{
				if (s == serial || s == "All")
				{
					match = true;
					break;
				}
			}
			if (!match)
				continue;
		}

		available++;
		auto* item = new QListWidgetItem(m_list);
		item->setText(QString::fromStdString(g->description));
		item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
		item->setCheckState(g->enabled ? Qt::Checked : Qt::Unchecked);
		item->setToolTip(QString::fromStdString(g->author));

		// Store description in UserRole for identification
		item->setData(Qt::UserRole, QString::fromStdString(g->description));
	}

	if (available == 0)
	{
		m_label->setText(m_label->text() + "\n\n" + tr("未找到适用于此游戏的金手指。"));
	}

	// Buttons
	auto* btn_layout = new QHBoxLayout();

	m_btn_all = new QPushButton(tr("全选"), this);
	m_btn_none = new QPushButton(tr("全不选"), this);

	btn_layout->addWidget(m_btn_all);
	btn_layout->addWidget(m_btn_none);
	btn_layout->addStretch();

	layout->addLayout(btn_layout);

	// Remember checkbox
	m_chk_remember = new QCheckBox(tr("记住选择（下次启动此游戏时自动应用相同的金手指）"), this);
	layout->addWidget(m_chk_remember);

	// Start/Cancel buttons
	auto* bottom_layout = new QHBoxLayout();
	bottom_layout->addStretch();

	m_btn_start = new QPushButton(tr("启动游戏"), this);
	m_btn_start->setMinimumWidth(120);
	m_btn_cancel = new QPushButton(tr("取消"), this);
	m_btn_cancel->setMinimumWidth(80);

	bottom_layout->addWidget(m_btn_start);
	bottom_layout->addWidget(m_btn_cancel);
	layout->addLayout(bottom_layout);

	// Connections
	connect(m_btn_all, &QPushButton::clicked, this, [this]() { select_all(true); });
	connect(m_btn_none, &QPushButton::clicked, this, [this]() { select_all(false); });
	connect(m_btn_start, &QPushButton::clicked, this, [this]()
	{
		// Apply selections to engine
		for (int i = 0; i < m_list->count(); i++)
		{
			auto* item = m_list->item(i);
			const QString desc = item->data(Qt::UserRole).toString();
			const bool enabled = item->checkState() == Qt::Checked;
			m_engine.set_enabled(desc.toStdString(), enabled);
		}
		m_confirmed = true;
		accept();
	});
	connect(m_btn_cancel, &QPushButton::clicked, this, [this]()
	{
		m_confirmed = false;
		reject();
	});
	connect(m_list, &QListWidget::itemChanged, this, &cheat_pre_boot_dialog::on_item_changed);
}

void cheat_pre_boot_dialog::select_all(bool checked)
{
	for (int i = 0; i < m_list->count(); i++)
	{
		auto* item = m_list->item(i);
		item->setCheckState(checked ? Qt::Checked : Qt::Unchecked);
	}
}

void cheat_pre_boot_dialog::on_item_changed(QListWidgetItem* /*item*/)
{
	// Could update UI based on selection
}

// ===========================================================================
// Add custom cheat sub-dialog
// ===========================================================================
cp_add_cheat_dialog::cp_add_cheat_dialog(QWidget* parent)
	: QDialog(parent)
{
	setWindowTitle(tr("添加自定义金手指"));
	setMinimumWidth(360);

	auto* form = new QFormLayout(this);

	m_edt_name = new QLineEdit(this);
	m_edt_name->setPlaceholderText(tr("例如：无限生命"));
	form->addRow(tr("名称:"), m_edt_name);

	m_edt_serial = new QLineEdit(this);
	m_edt_serial->setPlaceholderText(tr("留空则适用于所有游戏"));
	if (!Emu.GetTitleID().empty())
		m_edt_serial->setText(QString::fromStdString(Emu.GetTitleID()));
	form->addRow(tr("游戏序列号:"), m_edt_serial);

	m_cbx_type = new QComboBox(this);
	m_cbx_type->addItem("be32", static_cast<int>(cp_patch_type::be32));
	m_cbx_type->addItem("be16", static_cast<int>(cp_patch_type::be16));
	m_cbx_type->addItem("byte", static_cast<int>(cp_patch_type::byte));
	m_cbx_type->addItem("be64", static_cast<int>(cp_patch_type::be64));
	m_cbx_type->addItem("le32", static_cast<int>(cp_patch_type::le32));
	m_cbx_type->addItem("le16", static_cast<int>(cp_patch_type::le16));
	m_cbx_type->addItem("le64", static_cast<int>(cp_patch_type::le64));
	m_cbx_type->addItem("bef32", static_cast<int>(cp_patch_type::bef32));
	m_cbx_type->addItem("lef32", static_cast<int>(cp_patch_type::lef32));
	m_cbx_type->addItem("bef64", static_cast<int>(cp_patch_type::bef64));
	m_cbx_type->addItem("lef64", static_cast<int>(cp_patch_type::lef64));
	m_cbx_type->addItem("utf8", static_cast<int>(cp_patch_type::utf8));
	m_cbx_type->addItem("c_utf8", static_cast<int>(cp_patch_type::c_utf8));
	form->addRow(tr("类型:"), m_cbx_type);

	m_edt_offset = new QLineEdit(this);
	m_edt_offset->setPlaceholderText(tr("0x..."));
	form->addRow(tr("偏移:"), m_edt_offset);

	m_edt_value = new QLineEdit(this);
	m_edt_value->setPlaceholderText(tr("0x... 或数字或文本"));
	form->addRow(tr("值:"), m_edt_value);

	auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
	form->addRow(buttons);
	connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

QString cp_add_cheat_dialog::name() const     { return m_edt_name->text(); }
QString cp_add_cheat_dialog::serial() const   { return m_edt_serial->text(); }

cp_patch_type cp_add_cheat_dialog::patch_type() const
{
	return static_cast<cp_patch_type>(m_cbx_type->currentData().toInt());
}

u32 cp_add_cheat_dialog::offset() const
{
	const std::string s = m_edt_offset->text().toStdString();
	if (s.empty()) return 0;
	int base = 10;
	const char* p = s.c_str();
	if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; p += 2; }
	char* end = nullptr;
	unsigned long v = std::strtoul(p, &end, base);
	return (end == p) ? 0 : static_cast<u32>(v);
}

u64 cp_add_cheat_dialog::value() const
{
	const auto t = patch_type();
	if (t == cp_patch_type::utf8 || t == cp_patch_type::c_utf8)
		return 0;
	const std::string s = m_edt_value->text().toStdString();
	if (s.empty()) return 0;
	int base = 10;
	const char* p = s.c_str();
	if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; p += 2; }
	char* end = nullptr;
	unsigned long long v = std::strtoull(p, &end, base);
	return (end == p) ? 0 : static_cast<u64>(v);
}

QString cp_add_cheat_dialog::str_value() const
{
	const auto t = patch_type();
	if (t == cp_patch_type::utf8 || t == cp_patch_type::c_utf8)
		return m_edt_value->text();
	return {};
}
