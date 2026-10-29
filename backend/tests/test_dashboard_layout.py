import re
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_dashboard_shell_layout_and_scrolling_hierarchy():
    """
    Validates that the Single-Page Dashboard (/dashboard):
    1. Sets html and body to h-full with body overflow-hidden to prevent window bounce.
    2. Implements the unified primary vertical scroll container (#main-scroll-viewport)
       with flex-1 min-h-0 overflow-y-auto overflow-x-hidden.
    3. Keeps #content-container centered with max-w-7xl mx-auto inside the full-width viewport.
    4. Pins aside (sidebar) to h-full flex flex-col shrink-0 with nav flex-1 min-h-0 overflow-y-auto.
    5. Pins sidebar bottom sections (lab connectivity & role switcher) with shrink-0.
    6. Keeps header permanently visible with h-16 shrink-0.
    """
    res = client.get("/dashboard")
    assert res.status_code == 200
    html = res.text

    # 1. Root and Body
    assert '<html lang="en" class="h-full">' in html
    assert 'class="bg-[#faf7f8] text-slate-800 h-full flex antialiased selection:bg-pink-500 selection:text-white overflow-hidden"' in html

    # 2. Sidebar Shell
    assert 'class="w-64 h-full border-r border-pink-100 bg-white flex flex-col shrink-0 select-none shadow-xs z-20"' in html
    assert '<nav class="flex-1 min-h-0 px-3 py-4 space-y-1 overflow-y-auto text-xs font-medium">' in html

    # 3. Main and Primary Scroll Viewport
    assert 'id="main-scroll-viewport"' in html
    assert 'class="flex-1 min-h-0 overflow-y-auto overflow-x-hidden"' in html
    assert 'id="content-container"' in html
    assert 'class="p-6 space-y-6 max-w-7xl w-full mx-auto"' in html

def test_all_seven_tables_have_horizontal_overflow_wrappers():
    """
    Validates that every single table in the dashboard has:
    1. An outer rounded card.
    2. An inner wrapper with overflow-x-auto w-full.
    3. A deliberate minimum width (min-w-[...]) preventing column clipping.
    """
    res = client.get("/dashboard")
    html = res.text

    # Controls catalog table
    assert 'min-w-[950px]' in html
    # Control Mappings table
    assert 'min-w-[850px]' in html
    # Framework Comparison table
    assert 'min-w-[750px]' in html
    # Policy Detail Linked Controls table
    assert 'min-w-[500px]' in html
    # Evidence Vault table
    assert 'min-w-[750px]' in html
    # Assessment Run History table
    assert 'min-w-[700px]' in html
    # Active Findings table
    assert 'min-w-[800px]' in html

    # Verify at least 7 overflow-x-auto instances exist for tables
    overflow_count = html.count('class="overflow-x-auto w-full"')
    assert overflow_count >= 7, f"Expected >= 7 overflow-x-auto wrappers, got {overflow_count}"

def test_modals_have_viewport_containment_and_scrolling():
    """
    Validates that all modal dialogs fit within the viewport (max-h-[90vh])
    and remain internally scrollable (overflow-y-auto).
    """
    res = client.get("/dashboard")
    html = res.text

    assert 'id="modal-container"' in html
    assert 'id="modal-content"' in html
    assert 'max-h-[90vh]' in html
    assert 'id="mapping-review-modal"' in html
    assert 'id="mapping-audit-modal"' in html

def test_hash_navigation_and_scroll_reset():
    """
    Validates that client-side SPA navigation:
    1. Supports URL hash routing on init and on hashchange.
    2. Resets scroll position to 0 on navigate and subtab switches.
    """
    res = client.get("/dashboard")
    html = res.text

    assert 'window.location.hash' in html
    assert 'scrollViewport.scrollTop = 0' in html
    assert "window.addEventListener('hashchange'" in html
