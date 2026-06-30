#pragma once

#include "util/types.hpp"
#include "util/logs.hpp"
#include "util/yaml.hpp"

#include <QDialog>
#include <QTableWidget>
#include <QCheckBox>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QDialogButtonBox>

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <sstream>

// ============================================================================
// New independent cheat module — supports RPCS3 patch.yml format
// and user-defined custom cheats. Completely separate from the legacy
// cheat_manager and patch_engine.
// ============================================================================

// Patch types matching the patch.yml format
enum class cp_patch_type : u8
{
	invalid,
	byte,     // 8-bit
	le16,     // little-endian 16-bit
	be16,     // big-endian 16-bit
	le32,     // little-endian 32-bit
	be32,     // big-endian 32-bit
	le64,     // little-endian 64-bit
	be64,     // big-endian 64-bit
	lef32,    // little-endian float32
	bef32,    // big-endian float32
	lef64,    // little-endian float64
	bef64,    // big-endian float64
	utf8,     // UTF-8 string (not null-terminated)
	c_utf8,   // UTF-8 string (null-terminated)
};

// Returns the byte count that a patch type writes to memory (0 = variable/string)
inline u32 cp_type_size(cp_patch_type t)
{
	switch (t)
	{
	case cp_patch_type::byte:  return 1;
	case cp_patch_type::le16:
	case cp_patch_type::be16:  return 2;
	case cp_patch_type::le32:
	case cp_patch_type::be32:
	case cp_patch_type::le64:
	case cp_patch_type::be64:
	case cp_patch_type::lef32:
	case cp_patch_type::bef32: return 4;
	case cp_patch_type::lef64:
	case cp_patch_type::bef64: return 8;
	default: return 0;
	}
}

// A single patch line: [ type, offset, value ]
struct cp_patch_entry
{
	cp_patch_type type = cp_patch_type::invalid;
	u32 offset = 0;           // PS3 virtual address (resolved at apply time)
	u64 long_value = 0;       // integer value (host endianness)
	f64 double_value = 0.0;   // float value
	std::string str_value;    // string value (for utf8 / c_utf8)
	std::string original_offset; // original offset string (for display)
	std::string original_value;  // original value string (for display)
};

// A named group of patches (e.g. "60 FPS", "Infinite Health")
struct cp_cheat_group
{
	std::string description;          // e.g. "60 FPS"
	std::string author;
	std::string notes;
	std::string hash;                 // PPU-<hash> key
	std::vector<std::string> serials; // game serials (e.g. "BLUS30443")
	std::vector<cp_patch_entry> entries;
	bool enabled = false;             // active for periodic application
	bool is_custom = false;           // user-added (not from patch.yml)
};

// ---------------------------------------------------------------------------
// Core engine — singleton
// ---------------------------------------------------------------------------
class cheat_patch_engine
{
public:
	static cheat_patch_engine& get();

	// Load patches from a patch.yml file (appends to internal database)
	bool load_patch_yml(const std::string& path, std::string_view content = "", std::stringstream* log = nullptr);

	// Add a user-defined custom cheat (single entry)
	void add_custom_cheat(const std::string& name, const std::string& serial,
	                      cp_patch_type type, u32 offset, u64 value,
	                      const std::string& str_value = "");

	// Remove a cheat group by description (custom only)
	bool remove_cheat(const std::string& description);

	// Toggle a cheat group on/off
	void set_enabled(const std::string& description, bool enabled);

	// Apply all enabled cheats matching the current game to PS3 memory.
	// Safe to call periodically (timer-driven "freeze" effect).
	void apply_cheats();

	// Immediately apply a single group (one-shot, ignores enabled flag)
	bool apply_group(const cp_cheat_group& group);

	// Write one patch entry to memory at the given address
	static bool write_entry(u32 addr, const cp_patch_entry& entry);

	// Persist / restore enabled state
	void save_config();
	void load_config();

	// Accessors
	const std::vector<cp_cheat_group>& all_cheats() const { return m_cheats; }
	std::vector<cp_cheat_group*> cheats_for_serial(const std::string& serial);
	cp_cheat_group* find(const std::string& description);

	// Type helpers
	static cp_patch_type parse_type(std::string_view text);
	static std::string type_name(cp_patch_type t);
	static std::string format_value(const cp_patch_entry& e);

private:
	cheat_patch_engine();

	// Parse one YAML sequence node into patch entries (resolves `load` anchors)
	bool parse_patch_seq(YAML::Node seq, cp_cheat_group& group, const YAML::Node& root);

	std::vector<cp_cheat_group> m_cheats;
	std::unordered_map<std::string, bool> m_pending_enabled;
	const std::string m_config_file = "cheat_patch_config.yml";
};

// ---------------------------------------------------------------------------
// Dialog — UI for browsing / toggling / adding cheats
// ---------------------------------------------------------------------------
class cheat_patch_dialog : public QDialog
{
	Q_OBJECT
public:
	cheat_patch_dialog(QWidget* parent = nullptr);
	~cheat_patch_dialog();

	static cheat_patch_dialog* get_dlg(QWidget* parent = nullptr);

	cheat_patch_dialog(cheat_patch_dialog const&) = delete;
	void operator=(cheat_patch_dialog const&) = delete;

private:
	void refresh_list();
	void on_import();
	void on_add_custom();
	void on_apply_now();
	void on_item_changed(QTableWidgetItem* item);
	void on_context_menu(const QPoint& pos);

	QTableWidget* m_table = nullptr;
	QPushButton*  m_btn_import   = nullptr;
	QPushButton*  m_btn_add      = nullptr;
	QPushButton*  m_btn_apply    = nullptr;
	QCheckBox*    m_chk_auto     = nullptr;

	cheat_patch_engine& m_engine;

	static cheat_patch_dialog* s_inst;
};

// ---------------------------------------------------------------------------
// Small "add custom cheat" sub-dialog
// ---------------------------------------------------------------------------
class cp_add_cheat_dialog : public QDialog
{
	Q_OBJECT
public:
	explicit cp_add_cheat_dialog(QWidget* parent = nullptr);

	QString name() const;
	QString serial() const;
	cp_patch_type patch_type() const;
	u32 offset() const;
	u64 value() const;
	QString str_value() const;

private:
	QLineEdit*   m_edt_name   = nullptr;
	QLineEdit*   m_edt_serial = nullptr;
	QComboBox*   m_cbx_type   = nullptr;
	QLineEdit*   m_edt_offset = nullptr;
	QLineEdit*   m_edt_value  = nullptr;
};
