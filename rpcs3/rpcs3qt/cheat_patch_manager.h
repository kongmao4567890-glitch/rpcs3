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
#include <QListWidget>
#include <QLabel>

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <sstream>

// ============================================================================
// Independent cheat module — supports both RPCS3 patch.yml format
// and cheatsv2.yml format (write_bytes, find_replace, etc.)
// Completely separate from the legacy cheat_manager and patch_engine.
// ============================================================================

// ---------------------------------------------------------------------------
// Patch.yml format types (existing)
// ---------------------------------------------------------------------------
enum class cp_patch_type : u8
{
	invalid,
	byte, le16, be16, le32, be32, le64, be64,
	lef32, bef32, lef64, bef64, utf8, c_utf8,
};

inline u32 cp_type_size(cp_patch_type t)
{
	switch (t)
	{
	case cp_patch_type::byte:  return 1;
	case cp_patch_type::le16:
	case cp_patch_type::be16:  return 2;
	case cp_patch_type::le32:
	case cp_patch_type::be32:
	case cp_patch_type::lef32:
	case cp_patch_type::bef32: return 4;
	case cp_patch_type::le64:
	case cp_patch_type::be64:
	case cp_patch_type::lef64:
	case cp_patch_type::bef64: return 8;
	default: return 0;
	}
}

// ---------------------------------------------------------------------------
// Cheatsv2.yml code types (new)
// ---------------------------------------------------------------------------
enum class cp_v2_type : u8
{
	unknown,
	write_bytes,      // [write_bytes, OFFSET, HEX_DATA]
	find_replace,     // [find_replace, START, LENGTH, SEARCH_HEX, REPLACE_HEX]
	write_text,       // [write_text, OFFSET, TEXT]
	write_float,      // [write_float, OFFSET, FLOAT_VALUE]
	read_pointer,     // [read_pointer, BASE_OFFSET, OFFSET]
	copy_bytes,       // [copy_bytes, SRC, DST, LENGTH]
	write_condensed,  // [write_condensed, ADDR, VAL1, VAL2, VAL3]
	compared_cond,    // [compared_cond, ADDR, VALUE, LENGTH]
};

// ---------------------------------------------------------------------------
// A patch entry from patch.yml format
// ---------------------------------------------------------------------------
struct cp_patch_entry
{
	cp_patch_type type = cp_patch_type::invalid;
	u32 offset = 0;
	u64 long_value = 0;
	f64 double_value = 0.0;
	std::string str_value;
	std::string original_offset;
	std::string original_value;
};

// ---------------------------------------------------------------------------
// A code line from cheatsv2.yml format
// ---------------------------------------------------------------------------
struct cp_code_line
{
	cp_v2_type type = cp_v2_type::unknown;
	u32 address = 0;          // Primary address
	u32 param = 0;            // Search length / copy length / offset
	u32 dst_address = 0;      // Destination (copy_bytes)
	std::vector<u8> data;     // Bytes to write
	std::vector<u8> search;   // Search pattern (find_replace)
	std::vector<u8> replace;  // Replace pattern (find_replace)
	std::string text;         // Text (write_text)
	f64 fval = 0.0;           // Float (write_float)
	std::vector<u32> extra;   // Extra params (write_condensed)
	std::string raw;          // Raw representation for display
};

// ---------------------------------------------------------------------------
// A named group of cheats (supports both formats)
// ---------------------------------------------------------------------------
struct cp_cheat_group
{
	std::string description;          // Cheat name (e.g. "60 FPS")
	std::string author;
	std::string notes;
	std::string hash;                 // PPU-<hash> key (patch.yml)
	std::string game_key;             // Full game key (cheatsv2.yml)
	std::vector<std::string> serials; // Game serials
	std::vector<std::string> comments;

	// Patch.yml entries
	std::vector<cp_patch_entry> entries;

	// Cheatsv2 code lines
	std::vector<cp_code_line> codes;
	bool is_v2 = false;               // true if from cheatsv2.yml

	bool enabled = false;             // Active for application
	bool applied = false;             // Already applied (for one-shot codes)
	bool is_custom = false;           // User-added
};

// ---------------------------------------------------------------------------
// Core engine — singleton
// ---------------------------------------------------------------------------
class cheat_patch_engine
{
public:
	static cheat_patch_engine& get();

	// Load from patch.yml format
	bool load_patch_yml(const std::string& path, std::string_view content = "", std::stringstream* log = nullptr);

	// Load from cheatsv2.yml format
	bool load_cheatsv2(const std::string& path, std::string_view content = "");

	// Add a user-defined custom cheat
	void add_custom_cheat(const std::string& name, const std::string& serial,
	                      cp_patch_type type, u32 offset, u64 value,
	                      const std::string& str_value = "");

	bool remove_cheat(const std::string& description);
	void set_enabled(const std::string& description, bool enabled);

	// Apply all enabled cheats for the current game
	void apply_cheats();

	// Apply a single group
	bool apply_group(const cp_cheat_group& group);

	// Write one patch entry to memory
	static bool write_entry(u32 addr, const cp_patch_entry& entry);

	// Write raw bytes to memory
	static bool write_raw_bytes(u32 addr, const u8* data, u32 size);

	// Find and replace bytes in memory
	static bool find_replace_bytes(u32 start, u32 length,
	                               const u8* search, u32 search_len,
	                               const u8* replace, u32 replace_len);

	// Persist / restore enabled state
	void save_config();
	void load_config();

	// Accessors
	const std::vector<cp_cheat_group>& all_cheats() const { return m_cheats; }
	std::vector<cp_cheat_group*> cheats_for_serial(const std::string& serial);
	cp_cheat_group* find(const std::string& description);

	// Check if cheats are available for a serial
	bool has_cheats_for_serial(const std::string& serial) const;

	// Type helpers
	static cp_patch_type parse_type(std::string_view text);
	static std::string type_name(cp_patch_type t);
	static std::string format_value(const cp_patch_entry& e);
	static std::string v2_type_name(cp_v2_type t);

	// Parse a hex string into bytes
	static std::vector<u8> parse_hex(const std::string& hex);

private:
	cheat_patch_engine();
	bool parse_patch_seq(YAML::Node seq, cp_cheat_group& group, const YAML::Node& root);
	bool apply_v2_code(const cp_code_line& code);

	std::vector<cp_cheat_group> m_cheats;
	std::unordered_map<std::string, bool> m_pending_enabled;
	const std::string m_config_file = "cheat_patch_config.yml";
	bool m_v2_loaded = false;
};

// ---------------------------------------------------------------------------
// Main cheat manager dialog (browse / toggle / add cheats)
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
	void on_import_v2();
	void on_add_custom();
	void on_apply_now();
	void on_item_changed(QTableWidgetItem* item);
	void on_context_menu(const QPoint& pos);

	QTableWidget* m_table = nullptr;
	QPushButton*  m_btn_import   = nullptr;
	QPushButton*  m_btn_import_v2 = nullptr;
	QPushButton*  m_btn_add      = nullptr;
	QPushButton*  m_btn_apply    = nullptr;
	QCheckBox*    m_chk_auto     = nullptr;

	cheat_patch_engine& m_engine;

	static cheat_patch_dialog* s_inst;
};

// ---------------------------------------------------------------------------
// Pre-game-boot cheat selection dialog
// Shown before a game loads, lets user pick which cheats to enable
// ---------------------------------------------------------------------------
class cheat_pre_boot_dialog : public QDialog
{
	Q_OBJECT
public:
	explicit cheat_pre_boot_dialog(const std::string& serial, const std::string& game_name, QWidget* parent = nullptr);

	// Returns true if user clicked "Start Game"
	bool confirmed() const { return m_confirmed; }

private:
	void select_all(bool checked);
	void on_item_changed(QListWidgetItem* item);

	QLabel*      m_label      = nullptr;
	QListWidget* m_list       = nullptr;
	QPushButton* m_btn_all    = nullptr;
	QPushButton* m_btn_none   = nullptr;
	QPushButton* m_btn_start  = nullptr;
	QPushButton* m_btn_cancel = nullptr;
	QCheckBox*   m_chk_remember = nullptr;

	bool m_confirmed = false;
	cheat_patch_engine& m_engine;
	std::string m_serial;
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
