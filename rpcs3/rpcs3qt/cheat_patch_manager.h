#pragma once

#include "util/types.hpp"
#include "util/logs.hpp"
#include "util/yaml.hpp"
#include "Utilities/mutex.h"

#include <QDialog>
#include <QTreeWidget>
#include <QTableWidget>
#include <QCheckBox>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QDialogButtonBox>
#include <QListWidget>
#include <QLabel>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QGroupBox>

#include <string>
#include <vector>
#include <map>
#include <set>
#include <optional>
#include <unordered_map>
#include <sstream>

// ============================================================================
// Independent cheat engine — based on PR #11925 (Artemis cheats support)
// Supports both Artemis NCL format and cheatsv2.yml format
// Completely separate from the legacy cheat_manager and patch_engine.
// ============================================================================

// ---------------------------------------------------------------------------
// Cheat instruction types (from PR #11925)
// ---------------------------------------------------------------------------
enum class cheat_inst : u8
{
	write_bytes,
	or_bytes,
	and_bytes,
	xor_bytes,
	write_text,
	write_float,
	write_condensed,
	read_pointer,
	copy,
	paste,
	find_replace,
	compare_cond,
	and_compare_cond,
	copy_bytes,
};

// ---------------------------------------------------------------------------
// Cheat type: normal (one-shot) or constant (continuous)
// ---------------------------------------------------------------------------
enum class cheat_type : u8
{
	normal,
	constant,
};

// ---------------------------------------------------------------------------
// A single code line
// ---------------------------------------------------------------------------
struct cheat_code
{
	cheat_inst type{};
	std::string addr;
	std::string value;
	std::string opt1;
	std::string opt2;
};

// ---------------------------------------------------------------------------
// A complete cheat entry (may contain multiple code lines + variables)
// ---------------------------------------------------------------------------
struct cheat_entry
{
	cheat_type type{};
	std::string author;
	std::vector<cheat_code> codes;
	std::map<std::string, std::map<std::string, std::string>> variables;
	std::vector<std::string> comments;
	// Extra fields for cheatsv2.yml compatibility
	std::string game_key;
	std::vector<std::string> serials;
};

// ---------------------------------------------------------------------------
// Cheat executor — executes a single cheat entry
// Based on PR #11925 cheat_executor class
// ---------------------------------------------------------------------------
class cheat_executor
{
public:
	cheat_executor(std::string_view game_name, std::string_view cheat_name,
	               const cheat_entry& entry,
	               std::unordered_map<std::string, std::string> var_choices = {});

	bool is(std::string_view game_name, std::string_view cheat_name) const;
	bool operator<(const cheat_executor& rhs) const;
	bool execute(bool pause = true) const;
	std::pair<const std::string&, const std::string&> get_name() const;

private:
	std::string parse_value(const std::string& to_parse) const;
	std::optional<u32> parse_value_to_u32(const std::string& to_parse) const;
	std::optional<float> parse_value_to_float(const std::string& to_parse) const;
	std::optional<std::vector<u8>> parse_value_to_vector(const std::string& to_parse) const;

	static bool valid_range(u32 addr, u32 size);

	std::string m_game_name;
	std::string m_cheat_name;
	cheat_entry m_entry{};
	std::unordered_map<std::string, std::string> m_var_choices;
};

// ---------------------------------------------------------------------------
// Cheat engine — singleton, manages constant and queued cheats
// Based on PR #11925 cheat_engine class
// ---------------------------------------------------------------------------
class cheat_engine
{
public:
	const std::set<cheat_executor>& get_active_constant_cheats() const;
	const std::set<cheat_executor>& get_queued_cheats() const;

	void clear();
	bool activate_cheat(const std::string& game_name, const std::string& cheat_name,
	                    cheat_entry entry,
	                    std::unordered_map<std::string, std::string> var_choices = {});
	bool deactivate_cheat(const std::string& game_name, const std::string& cheat_name);
	void apply_queued_cheats();
	void operator()();

public:
	static constexpr std::string_view thread_name = "Cheat Thread";

private:
	shared_mutex m_mutex_constant, m_mutex_queued;
	std::set<cheat_executor> m_constant_cheats, m_queued_cheats;
};

extern cheat_engine g_cheat_engine;

// ---------------------------------------------------------------------------
// Cheat data storage — loads/saves cheats from YAML files
// Supports both Artemis NCL format and cheatsv2.yml format
// ---------------------------------------------------------------------------
class cheat_storage
{
public:
	static cheat_storage& get();

	// Load from cheatsv2.yml format
	bool load_cheatsv2(const std::string& path);

	// Load from Artemis NCL format
	bool load_ncl(const std::string& path);

	// Load from patch.yml format (legacy)
	bool load_patch_yml(const std::string& path);

	// Save/load persisted cheat data
	void save();
	void load();

	// Accessors
	const std::map<std::string, std::map<std::string, cheat_entry>>& all_cheats() const { return m_cheats; }
	std::map<std::string, cheat_entry>* cheats_for_game(const std::string& game_name);
	bool has_cheats_for_serial(const std::string& serial) const;

	// Add cheats
	void add_cheats(std::string name, std::map<std::string, cheat_entry> to_add);

	// Get all cheats matching a serial (searches game keys for serial)
	std::vector<std::pair<std::string, const cheat_entry*>> find_by_serial(const std::string& serial) const;

private:
	cheat_storage();
	std::map<std::string, std::map<std::string, cheat_entry>> m_cheats;
	bool m_v2_loaded = false;
	void ensure_v2_loaded();

	static constexpr const char* m_cheats_filename = "cheats_ncl.yml";
};

// ---------------------------------------------------------------------------
// Cheat manager dialog — browse/activate/import cheats
// Based on PR #11925 cheat_manager_dialog
// ---------------------------------------------------------------------------
class cheat_manager_dialog : public QDialog
{
	Q_OBJECT
public:
	cheat_manager_dialog(QWidget* parent = nullptr);
	~cheat_manager_dialog();

	static cheat_manager_dialog* get_dlg(QWidget* parent = nullptr);

	cheat_manager_dialog(cheat_manager_dialog const&) = delete;
	void operator=(cheat_manager_dialog const&) = delete;

private:
	void refresh_tree();
	void filter_cheats(const QString& game_id, const QString& term);
	void load_cheats();
	void save_cheats();

	QTreeWidget*   m_tree           = nullptr;
	QLineEdit*     m_edt_filter     = nullptr;
	QCheckBox*     m_chk_search_cur = nullptr;
	QLineEdit*     m_edt_author     = nullptr;
	QPlainTextEdit* m_pte_comments  = nullptr;
	QPushButton*   m_btn_import     = nullptr;
	QPushButton*   m_btn_import_v2  = nullptr;

	static inline const char* m_author_key    = "Author";
	static inline const char* m_comments_key  = "Comments";
	static inline const char* m_type_key      = "Type";
	static inline const char* m_codes_key     = "Codes";
	static inline const char* m_variables_key = "Variables";

	static cheat_manager_dialog* s_inst;
};

// ---------------------------------------------------------------------------
// Variables selection sub-dialog (for cheats with variables)
// ---------------------------------------------------------------------------
class cheat_variables_dialog : public QDialog
{
	Q_OBJECT
public:
	cheat_variables_dialog(const QString& title, const cheat_entry& entry, QWidget* parent = nullptr);
	std::unordered_map<std::string, std::string> get_choices();

private:
	std::vector<std::pair<std::string, QComboBox*>> m_combos;
};

// ---------------------------------------------------------------------------
// Pre-game-boot cheat selection dialog
// Shown before a game loads, lets user pick which cheats to activate
// ---------------------------------------------------------------------------
class cheat_pre_boot_dialog : public QDialog
{
	Q_OBJECT
public:
	explicit cheat_pre_boot_dialog(const std::string& serial, const std::string& game_name, QWidget* parent = nullptr);
	bool confirmed() const { return m_confirmed; }

private:
	void select_all(bool checked);

	QLabel*      m_label      = nullptr;
	QTreeWidget* m_tree       = nullptr;
	QPushButton* m_btn_all    = nullptr;
	QPushButton* m_btn_none   = nullptr;
	QPushButton* m_btn_start  = nullptr;
	QPushButton* m_btn_cancel = nullptr;

	bool m_confirmed = false;
};

// ---------------------------------------------------------------------------
// fmt_class_string specializations for cheat_inst and cheat_type
// Needed for YAML serialization
// ---------------------------------------------------------------------------
template <>
void fmt_class_string<cheat_type>::format(std::string& out, u64 arg);

template <>
void fmt_class_string<cheat_inst>::format(std::string& out, u64 arg);
