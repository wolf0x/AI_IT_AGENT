//! UI Automation via Windows IUIAutomation COM interface.
//! Provides accessibility tree walking, element finding, and interaction.
//! Pure Rust, Windows-only.

use serde_json::{json, Value};
use windows::core::Interface;
use windows::Win32::Foundation::*;
use windows::Win32::System::Com::*;
use windows::Win32::UI::Accessibility::*;

// ============================================================
// UI Element info
// ============================================================

/// Information about a UI element from the accessibility tree.
#[derive(Debug, Clone)]
pub struct UiElementInfo {
    pub role: String,
    pub name: String,
    pub class_name: String,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub patterns: Vec<String>,
    pub depth: u32,
}

impl UiElementInfo {
    pub fn to_json(&self) -> Value {
        json!({
            "role": self.role,
            "name": self.name,
            "class": self.class_name,
            "rect": { "x": self.x, "y": self.y, "width": self.width, "height": self.height },
            "patterns": self.patterns,
            "depth": self.depth,
        })
    }
}

// ============================================================
// COM initialization helper
// ============================================================

/// Initialize COM and create IUIAutomation instance.
fn create_automation() -> Result<IUIAutomation, String> {
    unsafe {
        // Initialize COM (ignore RPC_E_CHANGED_MODE if already initialized)
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

        let automation: IUIAutomation = CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("Failed to create IUIAutomation: {}", e))?;

        Ok(automation)
    }
}

// ============================================================
// UI Tree
// ============================================================

/// Get the accessibility tree for a window.
/// max_depth limits how deep to traverse (0 = unlimited).
pub fn get_ui_tree(hwnd_val: isize, max_depth: u32) -> Result<Vec<UiElementInfo>, String> {
    let automation = create_automation()?;
    let hwnd = HWND(hwnd_val as *mut _);

    unsafe {
        let root = automation
            .ElementFromHandle(hwnd)
            .map_err(|e| format!("Failed to get element from HWND: {}", e))?;

        let mut elements = Vec::new();
        let limit = if max_depth == 0 { 10 } else { max_depth };

        walk_tree(&automation, &root, 0, limit, &mut elements)?;

        Ok(elements)
    }
}

/// Recursively walk the UI tree.
fn walk_tree(
    automation: &IUIAutomation,
    element: &IUIAutomationElement,
    depth: u32,
    max_depth: u32,
    out: &mut Vec<UiElementInfo>,
) -> Result<(), String> {
    if depth > max_depth {
        return Ok(());
    }

    // Collect info for this element
    let info = get_element_info(element, depth)?;
    out.push(info);

    // Limit total elements to avoid huge trees
    if out.len() > 500 {
        return Ok(());
    }

    unsafe {
        // Create tree walker for children
        let condition = automation
            .CreateTrueCondition()
            .map_err(|e| format!("Failed to create condition: {}", e))?;

        let walker = automation
            .CreateTreeWalker(&condition)
            .map_err(|e| format!("Failed to create tree walker: {}", e))?;

        let child = walker.GetFirstChildElement(element);
        if let Ok(child) = child {
            walk_tree(automation, &child, depth + 1, max_depth, out)?;

            // Walk siblings
            let mut sibling = walker.GetNextSiblingElement(&child);
            while let Ok(sib) = sibling {
                if out.len() > 500 {
                    break;
                }
                walk_tree(automation, &sib, depth + 1, max_depth, out)?;
                sibling = walker.GetNextSiblingElement(&sib);
            }
        }
    }

    Ok(())
}

/// Extract info from a UI automation element.
fn get_element_info(element: &IUIAutomationElement, depth: u32) -> Result<UiElementInfo, String> {
    unsafe {
        let role = element
            .CurrentLocalizedControlType()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let name = element
            .CurrentName()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| String::new());

        let class_name = element
            .CurrentClassName()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| String::new());

        let rect = element.CurrentBoundingRectangle().unwrap_or_default();

        // Check available patterns
        let mut patterns = Vec::new();
        if element.GetCurrentPattern(UIA_InvokePatternId).is_ok() {
            patterns.push("invoke".to_string());
        }
        if element.GetCurrentPattern(UIA_ValuePatternId).is_ok() {
            patterns.push("value".to_string());
        }
        if element.GetCurrentPattern(UIA_TogglePatternId).is_ok() {
            patterns.push("toggle".to_string());
        }
        if element.GetCurrentPattern(UIA_SelectionItemPatternId).is_ok() {
            patterns.push("selection".to_string());
        }
        if element.GetCurrentPattern(UIA_ExpandCollapsePatternId).is_ok() {
            patterns.push("expand_collapse".to_string());
        }

        Ok(UiElementInfo {
            role,
            name,
            class_name,
            x: rect.left,
            y: rect.top,
            width: rect.right - rect.left,
            height: rect.bottom - rect.top,
            patterns,
            depth,
        })
    }
}

// ============================================================
// Find element
// ============================================================

/// Find a UI element by role and/or name within a window.
pub fn find_element(
    hwnd_val: isize,
    role: Option<&str>,
    name: Option<&str>,
    class_name: Option<&str>,
) -> Result<Vec<UiElementInfo>, String> {
    let automation = create_automation()?;
    let hwnd = HWND(hwnd_val as *mut _);

    unsafe {
        let root = automation
            .ElementFromHandle(hwnd)
            .map_err(|e| format!("Failed to get element from HWND: {}", e))?;

        // Build condition
        let condition = build_find_condition(&automation, role, name, class_name)?;

        // Find all matching elements (depth-first)
        let elements = root
            .FindAll(TreeScope_Descendants, &condition)
            .map_err(|e| format!("FindAll failed: {}", e))?;

        let count = elements.Length().unwrap_or(0);
        let mut results = Vec::new();

        for i in 0..count.min(50) {
            // Limit results
            if let Ok(elem) = elements.GetElement(i) {
                if let Ok(info) = get_element_info(&elem, 0) {
                    results.push(info);
                }
            }
        }

        Ok(results)
    }
}

/// Build a property condition for finding elements.
fn build_find_condition(
    automation: &IUIAutomation,
    role: Option<&str>,
    name: Option<&str>,
    class_name: Option<&str>,
) -> Result<IUIAutomationCondition, String> {
    unsafe {
        let mut conditions: Vec<IUIAutomationCondition> = Vec::new();

        if let Some(name) = name {
            let bstr = windows::core::BSTR::from(name);
            let cond = automation
                .CreatePropertyCondition(UIA_NamePropertyId, &windows::core::VARIANT::from(bstr))
                .map_err(|e| format!("Failed to create name condition: {}", e))?;
            conditions.push(cond);
        }

        if let Some(class) = class_name {
            let bstr = windows::core::BSTR::from(class);
            let cond = automation
                .CreatePropertyCondition(UIA_ClassNamePropertyId, &windows::core::VARIANT::from(bstr))
                .map_err(|e| format!("Failed to create class condition: {}", e))?;
            conditions.push(cond);
        }

        if let Some(role_str) = role {
            if let Some(control_type) = parse_control_type(role_str) {
                let cond = automation
                    .CreatePropertyCondition(UIA_ControlTypePropertyId, &windows::core::VARIANT::from(control_type))
                    .map_err(|e| format!("Failed to create role condition: {}", e))?;
                conditions.push(cond);
            }
        }

        match conditions.len() {
            0 => automation
                .CreateTrueCondition()
                .map_err(|e| format!("Failed to create true condition: {}", e)),
            1 => Ok(conditions.remove(0)),
            _ => {
                // AND all conditions together
                let mut result = conditions.remove(0);
                for cond in conditions {
                    result = automation
                        .CreateAndCondition(&result, &cond)
                        .map_err(|e| format!("Failed to create AND condition: {}", e))?;
                }
                Ok(result)
            }
        }
    }
}

// ============================================================
// Interact with elements
// ============================================================

/// Click a UI element found by role + name.
pub fn click_element(hwnd_val: isize, role: Option<&str>, name: Option<&str>) -> Result<String, String> {
    let automation = create_automation()?;
    let hwnd = HWND(hwnd_val as *mut _);

    unsafe {
        let root = automation
            .ElementFromHandle(hwnd)
            .map_err(|e| format!("Failed to get element: {}", e))?;

        let condition = build_find_condition(&automation, role, name, None)?;

        let element = root
            .FindFirst(TreeScope_Descendants, &condition)
            .map_err(|e| format!("FindFirst failed: {}", e))?;

        // Try InvokePattern first
        if let Ok(pattern) = element.GetCurrentPattern(UIA_InvokePatternId) {
            if let Ok(invoke) = pattern.cast::<IUIAutomationInvokePattern>() {
                invoke
                    .Invoke()
                    .map_err(|e| format!("Invoke failed: {}", e))?;
                return Ok("Clicked via InvokePattern".to_string());
            }
        }

        // Fallback: click at element center
        let rect = element.CurrentBoundingRectangle().unwrap_or_default();
        let cx = (rect.left + rect.right) / 2;
        let cy = (rect.top + rect.bottom) / 2;

        if cx > 0 && cy > 0 {
            super::input::mouse_move(cx as f64, cy as f64);
            std::thread::sleep(std::time::Duration::from_millis(50));
            super::input::mouse_click("left", 1);
            Ok(format!("Clicked at ({}, {}) via coordinate fallback", cx, cy))
        } else {
            Err("Element has no valid bounding rectangle".to_string())
        }
    }
}

/// Set the value of a UI element (e.g., text box).
pub fn set_value(
    hwnd_val: isize,
    role: Option<&str>,
    name: Option<&str>,
    value: &str,
) -> Result<String, String> {
    let automation = create_automation()?;
    let hwnd = HWND(hwnd_val as *mut _);

    unsafe {
        let root = automation
            .ElementFromHandle(hwnd)
            .map_err(|e| format!("Failed to get element: {}", e))?;

        let condition = build_find_condition(&automation, role, name, None)?;

        let element = root
            .FindFirst(TreeScope_Descendants, &condition)
            .map_err(|e| format!("FindFirst failed: {}", e))?;

        // Try ValuePattern
        if let Ok(pattern) = element.GetCurrentPattern(UIA_ValuePatternId) {
            if let Ok(value_pattern) = pattern.cast::<IUIAutomationValuePattern>() {
                let bstr = windows::core::BSTR::from(value);
                value_pattern
                    .SetValue(&bstr)
                    .map_err(|e| format!("SetValue failed: {}", e))?;
                return Ok(format!("Set value to: '{}'", value));
            }
        }

        // Fallback: focus + type
        let _ = element.SetFocus();
        std::thread::sleep(std::time::Duration::from_millis(50));
        // Select all + type
        super::input::key_press("ctrl+a").ok();
        std::thread::sleep(std::time::Duration::from_millis(20));
        super::input::type_text(value);
        Ok(format!("Typed value via keyboard fallback: '{}'", value))
    }
}

// ============================================================
// Control type parsing
// ============================================================

/// Parse a role name to a UIA_ControlType ID.
fn parse_control_type(role: &str) -> Option<i32> {
    let lower = role.to_lowercase();
    let ct = match lower.as_str() {
        "button" => UIA_ButtonControlTypeId,
        "edit" | "textbox" | "input" => UIA_EditControlTypeId,
        "checkbox" => UIA_CheckBoxControlTypeId,
        "combobox" | "dropdown" | "select" => UIA_ComboBoxControlTypeId,
        "list" => UIA_ListControlTypeId,
        "listitem" | "option" => UIA_ListItemControlTypeId,
        "menu" => UIA_MenuControlTypeId,
        "menuitem" => UIA_MenuItemControlTypeId,
        "radiobutton" | "radio" => UIA_RadioButtonControlTypeId,
        "slider" => UIA_SliderControlTypeId,
        "tab" | "tabitem" => UIA_TabItemControlTypeId,
        "text" | "label" => UIA_TextControlTypeId,
        "tree" => UIA_TreeControlTypeId,
        "treeitem" => UIA_TreeItemControlTypeId,
        "window" | "dialog" => UIA_WindowControlTypeId,
        "pane" | "panel" => UIA_PaneControlTypeId,
        "group" | "groupbox" => UIA_GroupControlTypeId,
        "toolbar" => UIA_ToolBarControlTypeId,
        "statusbar" => UIA_StatusBarControlTypeId,
        "scrollbar" => UIA_ScrollBarControlTypeId,
        "progressbar" => UIA_ProgressBarControlTypeId,
        "tooltip" => UIA_ToolTipControlTypeId,
        "table" | "datagrid" => UIA_DataGridControlTypeId,
        "hyperlink" | "link" => UIA_HyperlinkControlTypeId,
        "image" | "picture" => UIA_ImageControlTypeId,
        "separator" => UIA_SeparatorControlTypeId,
        "spinner" | "numeric" => UIA_SpinnerControlTypeId,
        "splitbutton" => UIA_SplitButtonControlTypeId,
        "thumb" => UIA_ThumbControlTypeId,
        "titlebar" => UIA_TitleBarControlTypeId,
        "custom" => UIA_CustomControlTypeId,
        _ => return None,
    };
    Some(ct.0)
}
