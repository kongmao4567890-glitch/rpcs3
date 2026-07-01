#include "stdafx.h"
#include "cheat_patch_manager.h"

#include "Emu/System.h"
#include "Emu/IdManager.h"
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

// LOG_CHANNEL is inline constinit, safe to define in multiple TUs
LOG_CHANNEL(log_cheat_patch);

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
			return std::nullopt;
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
			switch (*subtype) { case 1: return cheat_inst::copy; case 2: return cheat_inst::paste; default: return std::nullopt; }
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
		{ return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') || c == 'Z'; });
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
		case cheat_inst::write_bytes: case cheat_inst::or_bytes: case cheat_inst::and_bytes:
		case cheat_inst::xor_bytes: case cheat_inst::write_condensed: case cheat_inst::read_pointer:
		case cheat_inst::copy: case cheat_inst::paste: case cheat_inst::find_replace:
			if (!validate_hexzstr(args[2])) return std::nullopt;
			break;
		case cheat_inst::write_text: break;
		case cheat_inst::write_float:
			if (!validate_float(args[2])) return std::nullopt;
			break;
		case cheat_inst::compare_cond: case cheat_inst::and_compare_cond: case cheat_inst::copy_bytes:
			if (!validate_hexzstr(std::string_view(args[0].data() + 1, args[0].size() - 1))) return std::nullopt;
			if (!validate_hexzstr(args[2])) return std::nullopt;
			code.opt1 = args[0].data() + 1;
			break;
		default: return std::nullopt;
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
		for (; it != str.end() && *it == 'Z'; it++) var_name += *it;
		if (it == str.end() || var_name.empty() || *it != ']') return std::nullopt;
		it++;
		bool value = true;
		for (; it != str.end(); it++)
		{
			if (*it == ';' || *it == '[') { options.insert_or_assign(std::move(cur_name), std::move(cur_value)); cur_name = {}; cur_value = {}; value = true; continue; }
			if (*it == '=') { value = false; continue; }
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
				if (!entry.codes.empty()) entries.insert_or_assign(std::move(title), std::move(entry));
				title = {}; entry = {}; cur_line = 0; two_liner_code = std::nullopt;
				continue;
			}
			switch (cur_line)
			{
			case 0: title = line; break;
			case 1:
				if (!line.empty())
				{
					if (line[0] == '0') entry.type = cheat_exec_type::normal;
					else if (line[0] == '1' || line[0] == 'T') entry.type = cheat_exec_type::constant;
				}
				break;
			default:
			{
				auto code = parse_codeline(line, two_liner_code);
				if (!code)
				{
					if (cur_line == 2) { entry.author = line; break; }
					auto variable = parse_variable(line);
					if (!variable) { entry.comments.push_back(line); break; }
					entry.variables.insert_or_assign(variable->first, variable->second);
					break;
				}
				auto type = code->type;
				if (type == cheat_inst::write_condensed || type == cheat_inst::find_replace)
				{
					if (two_liner_code) { entry.codes.push_back(*code); two_liner_code = std::nullopt; break; }
					two_liner_code = code; break;
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
	return cheat_inst::write_bytes;
}

// ===========================================================================
// cheat_storage implementation
// ===========================================================================
cheat_storage& cheat_storage::get()
{
	static cheat_storage inst;
	return inst;
}

cheat_storage::cheat_storage() { load(); }

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
			if (load_cheatsv2(path.toStdString()))
			{
				// Persist loaded cheats so they survive emulator restarts
				save();
				log_cheat_patch.success("cheatsv2.yml loaded and persisted to cheats_ncl.yml");
			}
			break;
		}
	}
}

bool cheat_storage::load_cheatsv2(const std::string& path)
{
	fs::file f(path, fs::read + fs::isfile);
	if (!f) return false;
	auto [root, error] = yaml_load(f.to_string());
	if (!error.empty() || !root.IsMap()) return false;

	static const std::regex serial_re("([A-Z]{4}[0-9]{5})");
	usz count = 0;

	for (const auto& game_kv : root)
	{
		const std::string game_key = game_kv.first.Scalar();
		const YAML::Node& game_node = game_kv.second;
		if (!game_node.IsMap()) continue;

		std::string serial;
		std::smatch match;
		if (std::regex_search(game_key, match, serial_re)) serial = match[1].str();

		std::map<std::string, cheat_entry> cheats_to_add;
		for (const auto& cheat_kv : game_node)
		{
			const std::string cheat_name = cheat_kv.first.Scalar();
			const YAML::Node& cheat_node = cheat_kv.second;
			if (!cheat_node.IsMap()) continue;

			cheat_entry entry{};
			entry.game_key = game_key;
			if (!serial.empty()) entry.serials.push_back(serial);
			if (cheat_node["Author"]) entry.author = cheat_node["Author"].Scalar();
			if (cheat_node["Comments"] && cheat_node["Comments"].IsSequence())
				for (const auto& c : cheat_node["Comments"]) entry.comments.push_back(c.Scalar());
			if (cheat_node["Type"])
			{
				std::string t = cheat_node["Type"].Scalar();
				entry.type = (t == "Constant" || t == "constant") ? cheat_exec_type::constant : cheat_exec_type::normal;
			}

			if (cheat_node["Codes"] && cheat_node["Codes"].IsSequence())
			{
				for (const auto& code_item : cheat_node["Codes"])
				{
					if (!code_item.IsSequence() || code_item.size() < 2) continue;
					cheat_code code{};
					const std::string type_str = code_item[0].Scalar();
					code.type = v2_type_to_inst(type_str);
					if (code_item.size() >= 2) code.addr = code_item[1].Scalar();

					if (type_str == "find_replace" && code_item.size() >= 5)
					{
						std::string err;
						u32 start = get_yaml_node_value<u32>(code_item[1], err);
						u32 length = get_yaml_node_value<u32>(code_item[2], err);
						code.value = fmt::format("%X", start + length);
						code.opt1 = code_item[3].Scalar();
						code.opt2 = code_item[4].Scalar();
					}
					else if (type_str == "write_condensed" && code_item.size() >= 4)
					{
						std::string combined;
						for (usz i = 2; i < code_item.size(); i++) combined += code_item[i].Scalar();
						code.value = combined;
						code.opt1 = "4";
						code.opt2 = fmt::format("%d", code_item.size() - 2);
					}
					else if (type_str == "read_pointer" && code_item.size() >= 3) code.value = code_item[2].Scalar();
					else if (type_str == "copy_bytes" && code_item.size() >= 4) { code.value = code_item[2].Scalar(); code.opt1 = code_item[3].Scalar(); }
					else if (type_str == "copy" && code_item.size() >= 3) code.value = code_item[2].Scalar();
					else if (type_str == "paste" && code_item.size() >= 3) code.value = code_item[2].Scalar();
					else if ((type_str == "compare_cond" || type_str == "compared_cond" || type_str == "and_compare_cond") && code_item.size() >= 4)
					{ code.value = code_item[2].Scalar(); code.opt1 = code_item[3].Scalar(); }
					else if (code_item.size() >= 3) code.value = code_item[2].Scalar();

					entry.codes.push_back(std::move(code));
				}
			}
			if (!entry.codes.empty()) { cheats_to_add.insert_or_assign(std::move(cheat_name), std::move(entry)); count++; }
		}
		if (!cheats_to_add.empty()) m_cheats.insert_or_assign(game_key, std::move(cheats_to_add));
	}
	log_cheat_patch.success("Loaded %u v2 cheat groups from %s", count, path);
	return count > 0;
}

bool cheat_storage::load_ncl(const std::string& path)
{
	auto res = ncl_parser::parse_ncl(path);
	if (!res) return false;
	const QFileInfo file_info(QString::fromStdString(path));
	add_cheats(file_info.completeBaseName().toStdString(), std::move(*res));
	save();
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
		if (!kv.second.IsMap()) continue;

		std::map<std::string, cheat_entry> cheats_to_add;
		for (const auto& patch_kv : kv.second)
		{
			cheat_entry entry{};
			entry.game_key = key;
			std::string cheat_name = patch_kv.first.Scalar();
			if (!patch_kv.second.IsMap()) continue;
			if (patch_kv.second["Author"]) entry.author = patch_kv.second["Author"].Scalar();
			if (patch_kv.second["Games"] && patch_kv.second["Games"].IsMap())
				for (const auto& gk : patch_kv.second["Games"])
					if (gk.second.IsMap())
						for (const auto& sk : gk.second) entry.serials.push_back(sk.first.Scalar());
			if (patch_kv.second["Patch"] && patch_kv.second["Patch"].IsSequence())
				for (const auto& item : patch_kv.second["Patch"])
				{
					if (!item.IsSequence() || item.size() < 2) continue;
					cheat_code code{};
					code.type = cheat_inst::write_bytes;
					code.addr = item[1].Scalar();
					if (item.size() >= 3) code.value = item[2].Scalar();
					entry.codes.push_back(std::move(code));
				}
			if (!entry.codes.empty()) { cheats_to_add.insert_or_assign(std::move(cheat_name), std::move(entry)); count++; }
		}
		if (!cheats_to_add.empty()) m_cheats.insert_or_assign(key, std::move(cheats_to_add));
	}
	return count > 0;
}

void cheat_storage::save()
{
	const std::string cheats_path = patch_engine::get_patches_path();
	fs::create_path(cheats_path);
	fs::file f(cheats_path + m_cheats_filename, fs::rewrite);
	if (!f) return;

	YAML::Emitter out;
	out << YAML::BeginMap;
	for (const auto& [game_name, cheats] : m_cheats)
	{
		out << YAML::Key << game_name << YAML::BeginMap;
		for (const auto& [cheat_name, cheat] : cheats)
		{
			out << YAML::Key << cheat_name << YAML::BeginMap;
			out << YAML::Key << "Author" << YAML::Value << cheat.author;
			if (!cheat.comments.empty()) { out << YAML::Key << "Comments" << YAML::BeginSeq; for (const auto& c : cheat.comments) out << c; out << YAML::EndSeq; }
			out << YAML::Key << "Type" << YAML::Value << fmt::format("%s", cheat.type);
			out << YAML::Key << "Codes" << YAML::BeginSeq;
			for (const auto& code : cheat.codes)
				out << YAML::Flow << YAML::BeginSeq << fmt::format("%s", code.type) << code.addr << code.value << code.opt1 << code.opt2 << YAML::EndSeq;
			out << YAML::EndSeq;
			if (!cheat.variables.empty())
			{
				out << YAML::Key << "Variables" << YAML::BeginMap;
				for (const auto& [vn, vo] : cheat.variables) { out << YAML::Key << vn << YAML::BeginMap; for (const auto& [on, ov] : vo) out << YAML::Key << on << YAML::Value << ov; out << YAML::EndMap; }
				out << YAML::EndMap;
			}
			out << YAML::EndMap;
		}
		out << YAML::EndMap;
	}
	out << YAML::EndMap;
	if (out.good()) f.write(out.c_str(), out.size());
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
			if (const auto a = cheat_key.second["Author"]; a && a.IsScalar()) cheat_data.author = a.Scalar();
			if (const auto c = cheat_key.second["Comments"]; c && c.IsSequence()) for (const auto& cm : c) cheat_data.comments.push_back(cm.Scalar());
			if (const auto t = cheat_key.second["Type"]; t && t.IsScalar())
				cheat_data.type = (t.Scalar() == "Constant") ? cheat_exec_type::constant : cheat_exec_type::normal;
			if (const auto codes = cheat_key.second["Codes"]; codes && codes.IsSequence())
				for (const auto& code : codes)
				{
					if (!code.IsSequence() || code.size() < 5) continue;
					cheat_code ccode{};
					u64 type64;
					if (!cfg::try_to_enum_value(&type64, &fmt_class_string<cheat_inst>::format, code[0].Scalar())) continue;
					ccode.type = static_cast<cheat_inst>(::narrow<u8>(type64));
					ccode.addr = code[1].Scalar(); ccode.value = code[2].Scalar();
					ccode.opt1 = code[3].Scalar(); ccode.opt2 = code[4].Scalar();
					cheat_data.codes.push_back(std::move(ccode));
				}
			if (const auto vars = cheat_key.second["Variables"]; vars && vars.IsMap())
				for (const auto& var : vars)
				{
					const std::string var_name = var.first.Scalar();
					std::map<std::string, std::string> var_values;
					if (var.second.IsMap()) for (const auto& vo : var.second) var_values.insert_or_assign(vo.first.Scalar(), vo.second.Scalar());
					cheat_data.variables.insert_or_assign(var_name, var_values);
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
		if (game_name.find(serial) != std::string::npos) return true;
		for (const auto& [cheat_name, entry] : cheats)
			for (const auto& s : entry.serials)
				if (s == serial || s == "All") return true;
	}
	return false;
}

std::vector<std::pair<std::string, const cheat_entry*>> cheat_storage::find_by_serial(const std::string& serial) const
{
	std::vector<std::pair<std::string, const cheat_entry*>> result;
	for (const auto& [game_name, cheats] : m_cheats)
	{
		bool game_matches = (game_name.find(serial) != std::string::npos);
		for (const auto& [cheat_name, entry] : cheats)
		{
			if (game_matches) { result.emplace_back(cheat_name, &entry); continue; }
			for (const auto& s : entry.serials)
				if (s == serial || s == "All") { result.emplace_back(cheat_name, &entry); break; }
		}
	}
	return result;
}

// ===========================================================================
// cheat_patch_manager_dialog implementation
// ===========================================================================
cheat_patch_manager_dialog* cheat_patch_manager_dialog::s_inst = nullptr;

cheat_patch_manager_dialog::cheat_patch_manager_dialog(QWidget* parent)
	: QDialog(parent)
{
	setWindowTitle(tr("金手指管理器"));
	setObjectName("cheat_patch_manager_dialog");
	setMinimumSize(QSize(800, 400));

	auto* layout_main = new QVBoxLayout(this);

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

	connect(m_edt_filter, &QLineEdit::textChanged, this, [this](const QString& term)
	{ if (!m_chk_search_cur->isChecked()) filter_cheats("", term); });

	connect(m_chk_search_cur, &QCheckBox::stateChanged, this, [this](int state)
	{
		if (state == Qt::Checked) filter_cheats(QString::fromStdString(Emu.GetTitleID()), QString::fromStdString(Emu.GetTitle()));
		else filter_cheats("", m_edt_filter->text());
	});

	connect(m_btn_import, &QPushButton::clicked, this, [this](bool)
	{
		const QStringList paths = QFileDialog::getOpenFileNames(this, tr("选择要导入的 Artemis 金手指文件"), QString(), tr("Artemis 文件 (*.nlc *.NCL);;所有文件 (*.*)"));
		if (paths.isEmpty()) return;
		for (const auto& path : paths) cheat_storage::get().load_ncl(path.toStdString());
		cheat_storage::get().save();  // Persist to disk so cheats survive restart
		refresh_tree();
	});

	connect(m_btn_import_v2, &QPushButton::clicked, this, [this](bool)
	{
		const QString path = QFileDialog::getOpenFileName(this, tr("导入 cheatsv2.yml"), QString(), tr("YAML 文件 (*.yml *.yaml);;所有文件 (*.*)"));
		if (path.isEmpty()) return;
		cheat_storage::get().load_cheatsv2(path.toStdString());
		cheat_storage::get().save();  // Persist to disk so cheats survive restart
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
		if (!g_cheat_patch_engine.activate_cheat(game_name, cheat_name, cheat, var_choices))
		{
			g_cheat_patch_engine.deactivate_cheat(game_name, cheat_name);
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
		for (const auto& comment : cheat.comments) str_comments += comment + "\n";
		m_pte_comments->setPlainText(QString::fromStdString(str_comments));
	});

	cheat_storage::get().ensure_v2_loaded();
	refresh_tree();
}

cheat_patch_manager_dialog::~cheat_patch_manager_dialog() { s_inst = nullptr; }

cheat_patch_manager_dialog* cheat_patch_manager_dialog::get_dlg(QWidget* parent)
{
	if (!s_inst) s_inst = new cheat_patch_manager_dialog(parent);
	return s_inst;
}

void cheat_patch_manager_dialog::refresh_tree()
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
			if (entry.type == cheat_exec_type::constant) sub_entry->setCheckState(0, Qt::CheckState::Unchecked);
			top_entry->addChild(sub_entry);
		}
	}
	std::sort(items.begin(), items.end(), [](QTreeWidgetItem* a, QTreeWidgetItem* b) { return a->text(0).compare(b->text(0), Qt::CaseInsensitive) < 0; });
	m_tree->insertTopLevelItems(0, items);

	// Highlight active/queued
	const auto& constant_cheats = g_cheat_patch_engine.get_active_constant_cheats();
	for (const auto& cheat : constant_cheats)
	{
		const auto name = cheat.get_name();
		auto found = m_tree->findItems(QString::fromStdString(name.first), Qt::MatchExactly);
		if (found.empty()) continue;
		for (int i = 0; i < found[0]->childCount(); i++)
		{
			auto* child = found[0]->child(i);
			if (child->text(0).toStdString() == name.second) { child->setCheckState(0, Qt::Checked); break; }
		}
	}
	const auto& queued_cheats = g_cheat_patch_engine.get_queued_cheats();
	for (const auto& cheat : queued_cheats)
	{
		const auto name = cheat.get_name();
		auto found = m_tree->findItems(QString::fromStdString(name.first), Qt::MatchExactly);
		if (found.empty()) continue;
		for (int i = 0; i < found[0]->childCount(); i++)
		{
			auto* child = found[0]->child(i);
			if (child->text(0).toStdString() == name.second) { child->setBackground(0, QBrush(QColor(100, 200, 100, 80))); break; }
		}
	}
}

void cheat_patch_manager_dialog::filter_cheats(const QString& game_id, const QString& term)
{
	const QStringList words = term.split(" ", Qt::SkipEmptyParts);
	const auto* root = m_tree->invisibleRootItem();
	for (int i = 0; i < root->childCount(); i++)
	{
		auto* child = root->child(i);
		if (!game_id.isEmpty() && child->text(0).contains(game_id, Qt::CaseInsensitive)) { child->setHidden(false); continue; }
		if (std::all_of(words.begin(), words.end(), [child](const QString& word) { return child->text(0).contains(word, Qt::CaseInsensitive); }))
		{ child->setHidden(false); continue; }
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
	auto* layout_main = new QVBoxLayout(this);
	auto* gb_var = new QGroupBox(tr("变量:"));
	auto* layout_gb_var = new QVBoxLayout();
	for (const auto& [var_name, var_options] : entry.variables)
	{
		auto* layout_line = new QHBoxLayout();
		auto* label = new QLabel(QString::fromStdString(var_name));
		auto* cb = new QComboBox();
		for (const auto& [opt_name, opt_value] : var_options) cb->addItem(QString::fromStdString(opt_name), QString::fromStdString(opt_value));
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
		for (const auto& [var_name, combo] : m_combos) m_var_choices.insert_or_assign(var_name, combo->currentData().toString().toStdString());
		accept();
	});
	connect(btn_box, &QDialogButtonBox::rejected, this, &QDialog::reject);
	layout_main->addWidget(btn_box);
}

std::unordered_map<std::string, std::string> cheat_variables_dialog::get_choices() { return std::move(m_var_choices); }

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
		m_label->setText(tr("游戏序列号: %1\n\n请双击要启用的金手指，然后点击\"启动游戏\"。").arg(QString::fromStdString(serial)));
	else
		m_label->setText(tr("游戏: %1\n序列号: %2\n\n请双击要启用的金手指，然后点击\"启动游戏\"。").arg(QString::fromStdString(game_name)).arg(QString::fromStdString(serial)));
	m_label->setWordWrap(true);
	layout->addWidget(m_label);

	m_tree = new QTreeWidget(this);
	m_tree->setColumnCount(1);
	m_tree->setHeaderHidden(true);
	layout->addWidget(m_tree);

	auto cheats = cheat_storage::get().find_by_serial(serial);
	if (cheats.empty())
		m_label->setText(m_label->text() + "\n\n" + tr("未找到适用于此游戏的金手指。"));
	else
	{
		std::map<std::string, std::vector<std::pair<std::string, const cheat_entry*>>> grouped;
		for (const auto& [cheat_name, entry] : cheats)
		{
			std::string gk = entry->game_key.empty() ? "Cheats" : entry->game_key;
			grouped[gk].emplace_back(cheat_name, entry);
		}
		QList<QTreeWidgetItem*> items;
		for (const auto& [gk, cl] : grouped)
		{
			auto* top = new QTreeWidgetItem(QStringList(QString::fromStdString(gk)));
			for (const auto& [cn, ce] : cl)
			{
				auto* child = new QTreeWidgetItem();
				child->setText(0, QString::fromStdString(cn));
				if (ce->type == cheat_exec_type::constant) child->setCheckState(0, Qt::CheckState::Unchecked);
				top->addChild(child);
			}
			items.append(top);
		}
		m_tree->insertTopLevelItems(0, items);
	}

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

		bool found = false;
		for (const auto& c : g_cheat_patch_engine.get_active_constant_cheats()) if (c.is(game_name, cheat_name)) { found = true; break; }
		for (const auto& c : g_cheat_patch_engine.get_queued_cheats()) if (c.is(game_name, cheat_name)) { found = true; break; }

		if (found) { g_cheat_patch_engine.deactivate_cheat(game_name, cheat_name); item->setBackground(0, QBrush()); }
		else
		{
			std::unordered_map<std::string, std::string> var_choices;
			if (!cheat.variables.empty())
			{
				cheat_variables_dialog var_dlg(QString::fromStdString(cheat_name), cheat, this);
				if (var_dlg.exec() == QDialog::Rejected) return;
				var_choices = var_dlg.get_choices();
			}
			if (g_cheat_patch_engine.activate_cheat(game_name, cheat_name, cheat, var_choices, true))
				item->setBackground(0, QBrush(QColor(100, 200, 100, 80)));
		}
	});

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
	connect(m_btn_start, &QPushButton::clicked, this, [this]() { m_confirmed = true; accept(); });
	connect(m_btn_cancel, &QPushButton::clicked, this, [this]() { m_confirmed = false; reject(); });
}

void cheat_pre_boot_dialog::select_all(bool checked)
{
	const auto* root = m_tree->invisibleRootItem();
	for (int i = 0; i < root->childCount(); i++)
	{
		auto* top = root->child(i);
		const std::string game_name = top->text(0).toStdString();
		auto* cheats = cheat_storage::get().cheats_for_game(game_name);
		if (!cheats) continue;

		for (int j = 0; j < top->childCount(); j++)
		{
			auto* child = top->child(j);
			const std::string cheat_name = child->text(0).toStdString();
			if (!cheats->contains(cheat_name)) continue;
			const auto& cheat = cheats->at(cheat_name);

			bool found = false;
			for (const auto& c : g_cheat_patch_engine.get_active_constant_cheats()) if (c.is(game_name, cheat_name)) { found = true; break; }
			for (const auto& c : g_cheat_patch_engine.get_queued_cheats()) if (c.is(game_name, cheat_name)) { found = true; break; }

			if (checked && !found)
			{
				if (g_cheat_patch_engine.activate_cheat(game_name, cheat_name, cheat, {}, true))
					child->setBackground(0, QBrush(QColor(100, 200, 100, 80)));
			}
			else if (!checked && found)
			{
				g_cheat_patch_engine.deactivate_cheat(game_name, cheat_name);
				child->setBackground(0, QBrush());
			}
		}
	}
}
