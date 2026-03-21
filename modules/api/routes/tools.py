"""API routes for querying available scanning tools."""

from fastapi import APIRouter

from modules.tools.registry import TOOL_REGISTRY, CATEGORIES, SCAN_TYPE_CATEGORIES

router = APIRouter()


@router.get("/")
def list_tools():
    """List all available scanning tools grouped by category."""
    by_category = {}
    for name, tool in TOOL_REGISTRY.items():
        cat = tool["category"]
        if cat not in by_category:
            by_category[cat] = {
                "category": cat,
                "category_name": CATEGORIES.get(cat, cat),
                "tools": [],
            }
        by_category[cat]["tools"].append({
            "name": name,
            "description": tool["description"],
            "examples": tool.get("examples", []),
            "output_formats": tool.get("output_formats", []),
        })

    return {"categories": list(by_category.values()), "total_tools": len(TOOL_REGISTRY)}


@router.get("/scan-type/{scan_type}")
def tools_for_scan_type(scan_type: str):
    """List tools relevant to a specific scan type."""
    categories = SCAN_TYPE_CATEGORIES.get(scan_type)
    if categories is None:
        return {"error": f"Unknown scan type: {scan_type}. Available: {list(SCAN_TYPE_CATEGORIES.keys())}"}

    tools = []
    for name, tool in TOOL_REGISTRY.items():
        if tool["category"] in categories:
            tools.append({
                "name": name,
                "category": tool["category"],
                "description": tool["description"],
            })

    return {"scan_type": scan_type, "tools": tools, "total": len(tools)}


@router.get("/categories")
def list_categories():
    """List all tool categories."""
    return {"categories": CATEGORIES}


@router.get("/{tool_name}")
def get_tool(tool_name: str):
    """Get detailed info about a specific tool."""
    tool = TOOL_REGISTRY.get(tool_name)
    if not tool:
        return {"error": f"Unknown tool: {tool_name}. Available: {list(TOOL_REGISTRY.keys())}"}
    return {"name": tool_name, **tool}
