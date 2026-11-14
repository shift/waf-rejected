#!/bin/bash

# WAF Project Management Script
# Helper script for managing GitHub Project board status changes

PROJECT_ID="PVT_kwHNBnXOAQPAJA"
STATUS_FIELD_ID="PVTSSF_lAHNBnXOAQPAJM4M5e__"
PRIORITY_FIELD_ID="PVTSSF_lAHNBnXOAQPAJM4M5fAx"
COMPONENT_FIELD_ID="PVTSSF_lAHNBnXOAQPAJM4M5fBG"
SIZE_FIELD_ID="PVTSSF_lAHNBnXOAQPAJM4M5fBb"

# Status option IDs
TODO_ID="f75ad846"
IN_PROGRESS_ID="47fc9ee4"
DONE_ID="98236657"

# Priority option IDs
HIGH_PRIORITY_ID="d9eaa393"
MEDIUM_PRIORITY_ID="27dd1a04"
LOW_PRIORITY_ID="5c2c0707"

# Component option IDs
declare -A COMPONENT_IDS=(
    ["Security"]="34e74689"
    ["WASM"]="04a49141"
    ["Proxy"]="dae23c71"
    ["Config"]="66998588"
    ["Export"]="69b91097"
    ["Geo"]="78e5ecce"
    ["WebSocket"]="3b7db7d2"
    ["HTTP3"]="7e683762"
    ["AI"]="8909964a"
    ["Monitoring"]="983223a9"
    ["Core"]="2e03d0a7"
)

# Size option IDs
declare -A SIZE_IDS=(
    ["XS"]="7a380a08"
    ["S"]="402d84dd"
    ["M"]="b5e1eff5"
    ["L"]="41a939e7"
    ["XL"]="5a732cf3"
)

# Function to get item ID from issue URL
get_item_id() {
    local issue_url="$1"
    gh project item-list 3 --owner "@me" --format json | \
        jq -r ".items[] | select(.content.url == \"$issue_url\") | .id"
}

# Function to set status
set_status() {
    local item_id="$1"
    local status="$2"
    
    case "$status" in
        "todo"|"Todo")
            option_id="$TODO_ID"
            ;;
        "in-progress"|"In Progress")
            option_id="$IN_PROGRESS_ID"
            ;;
        "done"|"Done")
            option_id="$DONE_ID"
            ;;
        *)
            echo "Invalid status: $status. Use: todo, in-progress, done"
            return 1
            ;;
    esac
    
    gh project item-edit --id "$item_id" --project-id "$PROJECT_ID" \
        --field-id "$STATUS_FIELD_ID" --single-select-option-id "$option_id"
    
    echo "Set status to $status for item $item_id"
}

# Function to set priority
set_priority() {
    local item_id="$1"
    local priority="$2"
    
    case "$priority" in
        "high"|"High")
            option_id="$HIGH_PRIORITY_ID"
            ;;
        "medium"|"Medium")
            option_id="$MEDIUM_PRIORITY_ID"
            ;;
        "low"|"Low")
            option_id="$LOW_PRIORITY_ID"
            ;;
        *)
            echo "Invalid priority: $priority. Use: high, medium, low"
            return 1
            ;;
    esac
    
    gh project item-edit --id "$item_id" --project-id "$PROJECT_ID" \
        --field-id "$PRIORITY_FIELD_ID" --single-select-option-id "$option_id"
    
    echo "Set priority to $priority for item $item_id"
}

# Function to set component
set_component() {
    local item_id="$1"
    local component="$2"
    
    if [[ -n "${COMPONENT_IDS[$component]}" ]]; then
        option_id="${COMPONENT_IDS[$component]}"
    else
        echo "Invalid component: $component. Available: ${!COMPONENT_IDS[*]}"
        return 1
    fi
    
    gh project item-edit --id "$item_id" --project-id "$PROJECT_ID" \
        --field-id "$COMPONENT_FIELD_ID" --single-select-option-id "$option_id"
    
    echo "Set component to $component for item $item_id"
}

# Function to set size
set_size() {
    local item_id="$1"
    local size="$2"
    
    if [[ -n "${SIZE_IDS[$size]}" ]]; then
        option_id="${SIZE_IDS[$size]}"
    else
        echo "Invalid size: $size. Available: ${!SIZE_IDS[*]}"
        return 1
    fi
    
    gh project item-edit --id "$item_id" --project-id "$PROJECT_ID" \
        --field-id "$SIZE_FIELD_ID" --single-select-option-id "$option_id"
    
    echo "Set size to $size for item $item_id"
}

# Function to add new issue to project
add_issue() {
    local issue_url="$1"
    gh project item-add 3 --owner "@me" --url "$issue_url"
    echo "Added issue to project: $issue_url"
}

# Function to show project status
show_status() {
    echo "WAF-Rejected Development Project Status:"
    echo "========================================"
    gh project item-list 3 --owner "@me" --format json | \
        jq -r '.items[] | "\(.title) - \(.labels | join(","))"'
}

# Main command handler
case "$1" in
    "status")
        if [[ -n "$2" ]]; then
            set_status "$2" "$3"
        else
            show_status
        fi
        ;;
    "priority")
        set_priority "$2" "$3"
        ;;
    "component")
        set_component "$2" "$3"
        ;;
    "size")
        set_size "$2" "$3"
        ;;
    "add")
        add_issue "$2"
        ;;
    "item-id")
        get_item_id "$2"
        ;;
    *)
        echo "WAF Project Management Script"
        echo "Usage: $0 {status|priority|component|size|add|item-id} [args...]"
        echo ""
        echo "Commands:"
        echo "  status [item_id] [status]    - Set or show status"
        echo "  priority <item_id> <priority> - Set priority (high/medium/low)"
        echo "  component <item_id> <component> - Set component"
        echo "  size <item_id> <size>        - Set size (XS/S/M/L/XL)"
        echo "  add <issue_url>              - Add issue to project"
        echo "  item-id <issue_url>          - Get project item ID from issue URL"
        echo ""
        echo "Example: $0 status PVTI_lAHNBnXOAQPAJM4Hc7r0 in-progress"
        ;;
esac