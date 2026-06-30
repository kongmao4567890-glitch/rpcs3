#pragma once

#include "Utilities/cheat_engine.h"
#include "util/yaml.hpp"

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
#include <sstream>

// ============================================================================
// Cheat UI module — Qt-dependent dialogs and cheat storage
// Core engine types are in Utilities/cheat_engine.h
// ============================================================================

// ---------------------------------------------------------------------------
// Cheat data storage — loads/saves cheats from YAML files
// Supports both Artemis NCL format and cheatsv2.yml format
// ---------------------------------------------------------------------------
class cheat_storage
{
public:
	static cheat_storage& get();

	bool load_cheatsv2(const std::string& path);
	bool load_ncl(const std::string& path);
	bool load_patch_yml(const std::string& path);

	void save();
	void load();

	const std::map<std::string, std::map<std::string, cheat_entry>>& all_cheats() const { return m_cheats; }
	std::map<std::string, cheat_entry>* cheats_for_game(const std::string& game_name);
	bool has_cheats_for_serial(const std::string& serial) const;

	void add_cheats(std::string name, std::map<std::string, cheat_entry> to_add);

	std::vector<std::pair<std::string, const cheat_entry*>> find_by_serial(const std::string& serial) const;
	void ensure_v2_loaded();

private:
	cheat_storage();
	std::map<std::string, std::map<std::string, cheat_entry>> m_cheats;
	bool m_v2_loaded = false;
	static constexpr const char* m_cheats_filename = "cheats_ncl.yml";
};

// ---------------------------------------------------------------------------
// Cheat manager dialog — browse/activate/import cheats
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

	QTreeWidget*   m_tree           = nullptr;
	QLineEdit*     m_edt_filter     = nullptr;
	QCheckBox*     m_chk_search_cur = nullptr;
	QLineEdit*     m_edt_author     = nullptr;
	QPlainTextEdit* m_pte_comments  = nullptr;
	QPushButton*   m_btn_import     = nullptr;
	QPushButton*   m_btn_import_v2  = nullptr;

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
	std::unordered_map<std::string, std::string> m_var_choices;
};

// ---------------------------------------------------------------------------
// Pre-game-boot cheat selection dialog
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
