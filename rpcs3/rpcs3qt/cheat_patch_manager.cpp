#include "stdafx.h"
#include "cheat_patch_manager.h"

#include "Emu/System.h"
#include "Emu/system_config.h"
#include "Emu/Memory/vm.h"
#include "Emu/CPU/CPUThread.h"
#include "Emu/IdManager.h"
#include "Emu/Cell/PPUAnalyser.h"
#include "Emu/Cell/PPUInterpreter.h"
#include "Utilities/bin_patch.h" // for patch_engine::get_patches_path()

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

// ===========================================================================
// Logging
// ===========================================================================
LOG_CHANNEL(log_cheat_patch);

// ===========================================================================
// Type helpers
// ===========================================================================
cp_patch_type cheat_patch_engine::parse_type(std::string_view text)
{
	if (text == "byte")  return cp_patch_type::byte;
	if (text == "le16")  return cp_patch_type::le16;
	if (text == "be16")  return cp_patch_type::be16;
	if (text == "le32")  return cp_patch_type::le32;
	if (text == "be32")  return cp_patch_type::be32;
	if (text == "bd32")  return cp_patch_type::be32; // data hint == be32
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

	// Auto-load any patch.yml files from the RPCS3 patches directory
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
// YAML parsing
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
				// [ load, *anchor ] — yaml-cpp already resolved the anchor
				// The second element is the resolved sequence
				if (item[1] && item[1].IsSequence())
				{
					u32 modifier = 0;
					if (item.size() >= 3)
						modifier = item[2].as<u32>(0);

					for (const auto& sub : item[1])
					{
						// Create a temporary sequence node with modifier applied
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
								{
									entry.double_value = get_yaml_node_value<f32>(sub[2], err);
								}
								else if (entry.type == cp_patch_type::lef64 || entry.type == cp_patch_type::bef64)
								{
									entry.double_value = get_yaml_node_value<f64>(sub[2], err);
								}
								else
								{
									entry.long_value = get_yaml_node_value<u64>(sub[2], err);
									if (!err.empty())
									{
										entry.long_value = get_yaml_node_value<s64>(sub[2], err);
									}
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

		// Direct patch entry: [ type, offset, value ]
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
			{
				entry.double_value = get_yaml_node_value<f32>(item[2], err);
			}
			else if (type == cp_patch_type::lef64 || type == cp_patch_type::bef64)
			{
				entry.double_value = get_yaml_node_value<f64>(item[2], err);
			}
			else if (type == cp_patch_type::utf8 || type == cp_patch_type::c_utf8)
			{
				entry.str_value = item[2].Scalar();
			}
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
	{
		file_content = std::string(content);
	}
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

		// Skip Anchors and Version sections — anchors are resolved by yaml-cpp
		if (key == "Anchors" || key == "Version")
			continue;

		// Expect PPU-<hash> or SPU-<hash> keys
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

			// Extract author / notes
			if (patch_node["Author"])
				group.author = patch_node["Author"].Scalar();
			if (patch_node["Notes"])
				group.notes = patch_node["Notes"].Scalar();

			// Extract game serials from Games section
			if (patch_node["Games"] && patch_node["Games"].IsMap())
			{
				for (const auto& game_kv : patch_node["Games"])
				{
					if (game_kv.second.IsMap())
					{
						for (const auto& serial_kv : game_kv.second)
						{
							group.serials.push_back(serial_kv.first.Scalar());
						}
					}
				}
			}

			// Extract patch entries
			if (patch_node["Patch"] && patch_node["Patch"].IsSequence())
			{
				parse_patch_seq(patch_node["Patch"], group, root);
			}

			if (!group.entries.empty())
			{
				// Check if we already have this cheat (merge serials if so)
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
					// Restore enabled state from config
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
			save_config();
			return;
		}
	}
}

// ===========================================================================
// Memory writing
// ===========================================================================
bool cheat_patch_engine::write_entry(u32 addr, const cp_patch_entry& entry)
{
	const u32 size = cp_type_size(entry.type);
	if (size == 0 && entry.type != cp_patch_type::utf8 && entry.type != cp_patch_type::c_utf8)
		return false;

	// For string types compute actual size
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
		{
			std::memcpy(ptr, entry.str_value.data(), entry.str_value.size());
			break;
		}
		case cp_patch_type::c_utf8:
		{
			std::memcpy(ptr, entry.str_value.data(), entry.str_value.size());
			ptr[entry.str_value.size()] = '\0';
			break;
		}
		default:
			return false;
		}

		// Flush instruction cache if the patched region is executable
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

bool cheat_patch_engine::apply_group(const cp_cheat_group& group)
{
	if (Emu.IsStopped())
		return false;

	bool any = false;
	for (const auto& entry : group.entries)
	{
		if (write_entry(entry.offset, entry))
		{
			any = true;
		}
		else
		{
			log_cheat_patch.error("Failed to write cheat '%s' at 0x%x (%s)",
				group.description, entry.offset, type_name(entry.type));
		}
	}
	return any;
}

void cheat_patch_engine::apply_cheats()
{
	if (Emu.IsStopped())
		return;

	const std::string serial = Emu.GetTitleID();
	if (serial.empty())
		return;

	for (const auto& group : m_cheats)
	{
		if (!group.enabled)
			continue;

		// Custom cheats with empty serial apply to all games
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

		apply_group(group);
	}
}

// ===========================================================================
// Config persistence (enabled state)
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
		if (!g.serials.empty())
		{
			out << YAML::Key << "Serials" << YAML::Value << YAML::Flow << YAML::BeginSeq;
			for (const auto& s : g.serials)
				out << s;
			out << YAML::EndSeq;
		}
		// Save custom cheat entry data so they survive restart
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
			// Reconstruct custom cheat from saved data
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
			// For non-custom cheats, just store the enabled state to apply
			// when the patch.yml is loaded later
			m_pending_enabled[desc] = enabled;
		}
	}
}

// ===========================================================================
// Lookups
// ===========================================================================
std::vector<cp_cheat_group*> cheat_patch_engine::cheats_for_serial(const std::string& serial)
{
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

// ===========================================================================
// Dialog
// ===========================================================================
cheat_patch_dialog* cheat_patch_dialog::s_inst = nullptr;

cheat_patch_dialog::cheat_patch_dialog(QWidget* parent)
	: QDialog(parent)
	, m_engine(cheat_patch_engine::get())
{
	setWindowTitle(tr("Cheat Patch Manager"));
	setObjectName("cheat_patch_dialog");
	setMinimumSize(QSize(900, 500));

	auto* layout = new QVBoxLayout(this);

	// Toolbar
	auto* toolbar = new QHBoxLayout();
	m_btn_import = new QPushButton(tr("Import patch.yml"), this);
	m_btn_add    = new QPushButton(tr("Add Custom Cheat"), this);
	m_btn_apply  = new QPushButton(tr("Apply Now"), this);
	m_chk_auto   = new QCheckBox(tr("Auto-Apply"), this);
	m_chk_auto->setToolTip(tr("When checked, all enabled cheats are continuously re-applied to memory while a game is running."));
	m_chk_auto->setChecked(g_cfg.misc.cheat_patch_auto_apply.get());

	toolbar->addWidget(m_btn_import);
	toolbar->addWidget(m_btn_add);
	toolbar->addStretch();
	toolbar->addWidget(m_chk_auto);
	toolbar->addWidget(m_btn_apply);
	layout->addLayout(toolbar);

	// Cheat table
	m_table = new QTableWidget(this);
	m_table->setColumnCount(7);
	m_table->setHorizontalHeaderLabels(QStringList()
		<< tr("Enabled") << tr("Description") << tr("Author")
		<< tr("Type") << tr("Offset") << tr("Value") << tr("Serials"));
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_table->setContextMenuPolicy(Qt::CustomContextMenu);
	m_table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(m_table);

	// Connections
	connect(m_btn_import, &QPushButton::clicked, this, &cheat_patch_dialog::on_import);
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

		// Show first entry's type/offset/value (or "multiple" if more)
		if (g->entries.size() == 1)
		{
			const auto& e = g->entries[0];
			m_table->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(cheat_patch_engine::type_name(e.type))));
			m_table->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(e.original_offset)));
			m_table->setItem(row, 5, new QTableWidgetItem(QString::fromStdString(cheat_patch_engine::format_value(e))));
		}
		else
		{
			m_table->setItem(row, 3, new QTableWidgetItem(tr("%1 entries").arg(g->entries.size())));
			m_table->setItem(row, 4, new QTableWidgetItem(""));
			m_table->setItem(row, 5, new QTableWidgetItem(""));
		}

		QStringList sl;
		for (const auto& s : g->serials)
			sl << QString::fromStdString(s);
		m_table->setItem(row, 6, new QTableWidgetItem(sl.join(", ")));

		// Store description in first column's UserRole for identification
		chk->setData(Qt::UserRole, QString::fromStdString(g->description));

		// Custom cheats get a different background
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
	const QString path = QFileDialog::getOpenFileName(this, tr("Import patch.yml"), QString(), tr("YAML files (*.yml *.yaml);;All files (*)"));
	if (path.isEmpty())
		return;

	std::stringstream log;
	if (m_engine.load_patch_yml(path.toStdString(), "", &log))
	{
		QMessageBox::information(this, tr("Import"), tr("Cheats imported successfully."));
		refresh_list();
	}
	else
	{
		QMessageBox::warning(this, tr("Import"), tr("Failed to import cheats. Check log for details."));
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
		QMessageBox::warning(this, tr("Add Cheat"), tr("Name cannot be empty."));
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
		QMessageBox::information(this, tr("Apply"), tr("No game is running."));
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

	QMessageBox::information(this, tr("Apply"), tr("Applied %n cheat group(s).", "", applied));
}

void cheat_patch_dialog::on_item_changed(QTableWidgetItem* item)
{
	if (!item)
		return;

	if (item->column() != 0)
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
		auto* action_del = menu.addAction(tr("Delete Custom Cheat"));
		connect(action_del, &QAction::triggered, this, [this, desc]()
		{
			if (m_engine.remove_cheat(desc))
				refresh_list();
		});
	}

	if (g && !g->entries.empty())
	{
		auto* action_detail = menu.addAction(tr("View Details"));
		connect(action_detail, &QAction::triggered, this, [this, g]()
		{
			QString html = QString("<h3>%1</h3>").arg(QString::fromStdString(g->description));
			html += QString("<p><b>Author:</b> %1<br>").arg(QString::fromStdString(g->author));
			html += QString("<b>Hash:</b> %1<br>").arg(QString::fromStdString(g->hash));
			html += QString("<b>Notes:</b> %1</p>").arg(QString::fromStdString(g->notes));
			html += "<table border='1' cellpadding='4'><tr><th>Type</th><th>Offset</th><th>Value</th></tr>";
			for (const auto& e : g->entries)
			{
				html += QString("<tr><td>%1</td><td>%2</td><td>%3</td></tr>")
					.arg(QString::fromStdString(cheat_patch_engine::type_name(e.type)))
					.arg(QString::fromStdString(e.original_offset))
					.arg(QString::fromStdString(cheat_patch_engine::format_value(e)));
			}
			html += "</table>";

			QMessageBox::information(this, tr("Cheat Details"), html);
		});
	}

	if (!menu.isEmpty())
		menu.exec(m_table->viewport()->mapToGlobal(pos));
}

// ===========================================================================
// Add custom cheat sub-dialog
// ===========================================================================
cp_add_cheat_dialog::cp_add_cheat_dialog(QWidget* parent)
	: QDialog(parent)
{
	setWindowTitle(tr("Add Custom Cheat"));
	setMinimumWidth(360);

	auto* form = new QFormLayout(this);

	m_edt_name = new QLineEdit(this);
	m_edt_name->setPlaceholderText(tr("e.g. Infinite Health"));
	form->addRow(tr("Name:"), m_edt_name);

	m_edt_serial = new QLineEdit(this);
	m_edt_serial->setPlaceholderText(tr("Leave empty for all games"));
	// Pre-fill with current game serial if running
	if (!Emu.GetTitleID().empty())
		m_edt_serial->setText(QString::fromStdString(Emu.GetTitleID()));
	form->addRow(tr("Game Serial:"), m_edt_serial);

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
	form->addRow(tr("Type:"), m_cbx_type);

	m_edt_offset = new QLineEdit(this);
	m_edt_offset->setPlaceholderText(tr("0x..."));
	form->addRow(tr("Offset:"), m_edt_offset);

	m_edt_value = new QLineEdit(this);
	m_edt_value->setPlaceholderText(tr("0x... or number or text"));
	form->addRow(tr("Value:"), m_edt_value);

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
