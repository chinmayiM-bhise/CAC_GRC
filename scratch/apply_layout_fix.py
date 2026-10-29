import re

file_path = "backend/app/static/index.html"

with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. HTML tag
assert '<html lang="en">' in content, "HTML tag assertion failed"
content = content.replace('<html lang="en">', '<html lang="en" class="h-full">', 1)

# 2. Scrollbars style
old_style = """  <style>
    /* Custom light theme scrollbars */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #fdf2f8; }
    ::-webkit-scrollbar-thumb { background: #f472b6; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #db2777; }
  </style>"""

new_style = """  <style>
    /* Custom light theme scrollbars */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #fdf2f8; }
    ::-webkit-scrollbar-thumb { background: #f472b6; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #db2777; }

    /* Cross-browser Firefox scrollbar styling */
    * {
      scrollbar-width: thin;
      scrollbar-color: #f472b6 #fdf2f8;
    }
  </style>"""

assert old_style in content, "old_style assertion failed"
content = content.replace(old_style, new_style, 1)

# 3. Body & Aside
old_body_aside = """<body class="bg-[#faf7f8] text-slate-800 min-h-screen flex antialiased selection:bg-pink-500 selection:text-white">

  <!-- Persistent Enterprise Sidebar Navigation (White & Pink Theme) -->
  <aside class="w-64 border-r border-pink-100 bg-white flex flex-col shrink-0 select-none shadow-xs">"""

new_body_aside = """<body class="bg-[#faf7f8] text-slate-800 h-full flex antialiased selection:bg-pink-500 selection:text-white overflow-hidden">

  <!-- Persistent Enterprise Sidebar Navigation (White & Pink Theme) -->
  <aside class="w-64 h-full border-r border-pink-100 bg-white flex flex-col shrink-0 select-none shadow-xs z-20">"""

assert old_body_aside in content, "old_body_aside assertion failed"
content = content.replace(old_body_aside, new_body_aside, 1)

# 4. Nav min-h-0
old_nav = '<nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto text-xs font-medium">'
new_nav = '<nav class="flex-1 min-h-0 px-3 py-4 space-y-1 overflow-y-auto text-xs font-medium">'
assert old_nav in content, "old_nav assertion failed"
content = content.replace(old_nav, new_nav, 1)

# 5. Sidebar bottom items shrink-0
old_target_box = '    <!-- Target Connectivity Quick Status -->\n    <div class="p-3 border-t border-pink-100 bg-pink-50/40 text-[11px]">'
new_target_box = '    <!-- Target Connectivity Quick Status -->\n    <div class="p-3 border-t border-pink-100 bg-pink-50/40 text-[11px] shrink-0">'
assert old_target_box in content, "old_target_box assertion failed"
content = content.replace(old_target_box, new_target_box, 1)

old_user_box = '    <!-- Active User & Role Context -->\n    <div class="p-3 border-t border-pink-100 bg-white flex items-center justify-between text-xs">'
new_user_box = '    <!-- Active User & Role Context -->\n    <div class="p-3 border-t border-pink-100 bg-white flex items-center justify-between text-xs shrink-0">'
assert old_user_box in content, "old_user_box assertion failed"
content = content.replace(old_user_box, new_user_box, 1)

# 6. Main & Content-Container Scroll Viewport
old_main_viewport = """  <!-- Main Application Body -->
  <main class="flex-1 flex flex-col min-w-0 overflow-hidden bg-[#faf7f8]">
    <!-- Top Enterprise Header -->
    <header class="h-16 border-b border-pink-100 bg-white/90 backdrop-blur px-6 flex items-center justify-between shrink-0 shadow-2xs">
      <div class="flex items-center space-x-3 text-xs text-slate-500">
        <span id="page-breadcrumb">Compliance / <strong class="text-slate-900">Overview</strong></span>
      </div>

      <!-- Action Center -->
      <div class="flex items-center space-x-2.5">
        <button onclick="openAuditDossierModal()" class="bg-white hover:bg-pink-50 text-slate-700 border border-slate-200 hover:border-pink-300 text-xs font-semibold px-3 py-1.5 rounded-lg transition flex items-center space-x-1.5 shadow-2xs">
          <svg class="w-3.5 h-3.5 text-pink-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          <span>Generate Audit Report</span>
        </button>

        <button onclick="triggerAssessment(true)" id="btn-assess-sim" class="bg-pink-600 hover:bg-pink-700 text-white text-xs font-semibold px-3.5 py-1.5 rounded-lg transition flex items-center space-x-1.5 shadow-sm shadow-pink-200">
          <svg class="w-3.5 h-3.5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
          <span>Run Assessment Sweep</span>
        </button>
      </div>
    </header>

    <!-- Dynamic Section Viewport -->
    <div id="content-container" class="flex-1 overflow-y-auto p-6 space-y-6 max-w-7xl w-full mx-auto">
      <!-- Dynamically Rendered by View Navigator -->
    </div>
  </main>"""

new_main_viewport = """  <!-- Main Application Body -->
  <main class="flex-1 flex flex-col h-full min-w-0 overflow-hidden bg-[#faf7f8]">
    <!-- Top Enterprise Header -->
    <header class="h-16 border-b border-pink-100 bg-white/95 backdrop-blur px-6 flex items-center justify-between shrink-0 shadow-2xs z-10">
      <div class="flex items-center space-x-3 text-xs text-slate-500">
        <span id="page-breadcrumb">Compliance / <strong class="text-slate-900">Overview</strong></span>
      </div>

      <!-- Action Center -->
      <div class="flex items-center space-x-2.5">
        <button onclick="openAuditDossierModal()" class="bg-white hover:bg-pink-50 text-slate-700 border border-slate-200 hover:border-pink-300 text-xs font-semibold px-3 py-1.5 rounded-lg transition flex items-center space-x-1.5 shadow-2xs">
          <svg class="w-3.5 h-3.5 text-pink-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          <span>Generate Audit Report</span>
        </button>

        <button onclick="triggerAssessment(true)" id="btn-assess-sim" class="bg-pink-600 hover:bg-pink-700 text-white text-xs font-semibold px-3.5 py-1.5 rounded-lg transition flex items-center space-x-1.5 shadow-sm shadow-pink-200">
          <svg class="w-3.5 h-3.5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
          <span>Run Assessment Sweep</span>
        </button>
      </div>
    </header>

    <!-- Dynamic Section Viewport (Unified Primary Vertical Scroll Container) -->
    <div id="main-scroll-viewport" class="flex-1 min-h-0 overflow-y-auto overflow-x-hidden">
      <div id="content-container" class="p-6 space-y-6 max-w-7xl w-full mx-auto">
        <!-- Dynamically Rendered by View Navigator -->
      </div>
    </div>
  </main>"""

assert old_main_viewport in content, "old_main_viewport assertion failed"
content = content.replace(old_main_viewport, new_main_viewport, 1)

# 7. Modals
old_modals = """  <!-- Global Modal Container (White & Pink Light Theme) -->
  <div id="modal-container" class="fixed inset-0 bg-slate-900/30 backdrop-blur-xs z-50 flex items-center justify-center p-4 hidden">
    <div id="modal-content" class="bg-white border border-pink-100 rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden text-xs">
      <!-- Dynamically Populated Modal -->
    </div>
  </div>

  <!-- Policy Mapping Review Modal -->
  <div id="mapping-review-modal" class="hidden fixed inset-0 bg-slate-900/30 backdrop-blur-xs z-50 flex items-center justify-center p-4">
    <div class="bg-white border border-pink-100 rounded-2xl max-w-lg w-full p-6 text-xs shadow-2xl">
      <h3 class="text-slate-900 font-bold text-sm mb-2">Human Review of Candidate Mapping</h3>
      <div class="bg-amber-50 border border-amber-200 text-amber-900 p-3 rounded-lg text-xs font-semibold mb-3">
        <span>Regulatory Assurance Notice:</span> A similarity score NEVER certifies regulatory compliance or control effectiveness.
      </div>
      <div class="space-y-3">
        <div>
          <label class="block text-slate-700 font-semibold mb-1">Review Notes (Mandatory)</label>
          <textarea id="review-notes-input" rows="3" class="w-full bg-white border border-slate-200 rounded-lg p-2 text-slate-800 focus:border-pink-500" placeholder="Enter auditor justification..."></textarea>
        </div>
        <div class="flex justify-end space-x-2 pt-2">
          <button id="btn-submit-review" class="px-3.5 py-1.5 bg-pink-600 hover:bg-pink-700 text-white rounded-lg font-semibold shadow-xs">Commit Decision</button>
          <span class="hidden">HUMAN_APPROVED</span>
          <span class="hidden">REJECTED</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Mapping Review Audit Trail Modal -->
  <div id="mapping-audit-modal" class="hidden fixed inset-0 bg-slate-900/30 backdrop-blur-xs z-50 flex items-center justify-center p-4">
    <div class="bg-white border border-pink-100 rounded-2xl max-w-xl w-full p-6 text-xs shadow-2xl">"""

new_modals = """  <!-- Global Modal Container (White & Pink Light Theme) -->
  <div id="modal-container" class="fixed inset-0 bg-slate-900/30 backdrop-blur-xs z-50 flex items-center justify-center p-4 overflow-y-auto hidden">
    <div id="modal-content" class="bg-white border border-pink-100 rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden text-xs max-h-[90vh] flex flex-col my-auto">
      <!-- Dynamically Populated Modal -->
    </div>
  </div>

  <!-- Policy Mapping Review Modal -->
  <div id="mapping-review-modal" class="hidden fixed inset-0 bg-slate-900/30 backdrop-blur-xs z-50 flex items-center justify-center p-4 overflow-y-auto">
    <div class="bg-white border border-pink-100 rounded-2xl max-w-lg w-full p-6 text-xs shadow-2xl max-h-[90vh] overflow-y-auto my-auto">
      <h3 class="text-slate-900 font-bold text-sm mb-2">Human Review of Candidate Mapping</h3>
      <div class="bg-amber-50 border border-amber-200 text-amber-900 p-3 rounded-lg text-xs font-semibold mb-3">
        <span>Regulatory Assurance Notice:</span> A similarity score NEVER certifies regulatory compliance or control effectiveness.
      </div>
      <div class="space-y-3">
        <div>
          <label class="block text-slate-700 font-semibold mb-1">Review Notes (Mandatory)</label>
          <textarea id="review-notes-input" rows="3" class="w-full bg-white border border-slate-200 rounded-lg p-2 text-slate-800 focus:border-pink-500" placeholder="Enter auditor justification..."></textarea>
        </div>
        <div class="flex justify-end space-x-2 pt-2">
          <button id="btn-submit-review" class="px-3.5 py-1.5 bg-pink-600 hover:bg-pink-700 text-white rounded-lg font-semibold shadow-xs">Commit Decision</button>
          <span class="hidden">HUMAN_APPROVED</span>
          <span class="hidden">REJECTED</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Mapping Review Audit Trail Modal -->
  <div id="mapping-audit-modal" class="hidden fixed inset-0 bg-slate-900/30 backdrop-blur-xs z-50 flex items-center justify-center p-4 overflow-y-auto">
    <div class="bg-white border border-pink-100 rounded-2xl max-w-xl w-full p-6 text-xs shadow-2xl max-h-[90vh] overflow-y-auto my-auto">"""

assert old_modals in content, "old_modals assertion failed"
content = content.replace(old_modals, new_modals, 1)

# 8. Table 1: Controls table in renderControls
old_table1 = """          <!-- Controls Table -->
          <div class="bg-white border border-pink-100/80 rounded-2xl overflow-hidden shadow-xs">
            <table class="w-full text-left text-xs text-slate-700">
              <thead class="bg-pink-50/50 border-b border-pink-100 text-slate-600 font-bold uppercase text-[10px] tracking-wider">
                <tr>
                  <th class="px-4 py-3">Control ID</th>
                  <th class="px-4 py-3">Framework</th>
                  <th class="px-4 py-3">Title & Family</th>
                  <th class="px-4 py-3">Assessment Method</th>
                  <th class="px-4 py-3">Policy Mapping</th>
                  <th class="px-4 py-3">EW-CES State</th>
                  <th class="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody id="controls-table-body" class="divide-y divide-slate-100">
                <!-- Dynamically Rendered -->
              </tbody>
            </table>
          </div>"""

new_table1 = """          <!-- Controls Table -->
          <div class="bg-white border border-pink-100/80 rounded-2xl shadow-xs overflow-hidden">
            <div class="overflow-x-auto w-full">
              <table class="w-full min-w-[950px] text-left text-xs text-slate-700">
                <thead class="bg-pink-50/50 border-b border-pink-100 text-slate-600 font-bold uppercase text-[10px] tracking-wider">
                  <tr>
                    <th class="px-4 py-3 whitespace-nowrap">Control ID</th>
                    <th class="px-4 py-3 whitespace-nowrap">Framework</th>
                    <th class="px-4 py-3">Title & Family</th>
                    <th class="px-4 py-3 whitespace-nowrap">Assessment Method</th>
                    <th class="px-4 py-3 whitespace-nowrap">Policy Mapping</th>
                    <th class="px-4 py-3 whitespace-nowrap">EW-CES State</th>
                    <th class="px-4 py-3 text-right whitespace-nowrap">Action</th>
                  </tr>
                </thead>
                <tbody id="controls-table-body" class="divide-y divide-slate-100">
                  <!-- Dynamically Rendered -->
                </tbody>
              </table>
            </div>
          </div>"""

assert old_table1 in content, "old_table1 assertion failed"
content = content.replace(old_table1, new_table1, 1)

# 9. Table 2: Mappings table in renderMappingsReviewSubTab
old_table2 = """          <!-- Mappings Table -->
          <div class="bg-white border border-pink-100/80 rounded-2xl overflow-hidden shadow-xs">
            <table class="w-full text-left text-xs text-slate-700">
              <thead class="bg-pink-50/50 border-b border-pink-100 text-slate-600 font-bold uppercase text-[10px] tracking-wider">
                <tr>
                  <th class="px-4 py-3">Policy</th>
                  <th class="px-4 py-3">Framework Control</th>
                  <th class="px-4 py-3">Mapping Status</th>
                  <th class="px-4 py-3">Confidence</th>
                  <th class="px-4 py-3">Rationale & Audit</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-100">"""

new_table2 = """          <!-- Mappings Table -->
          <div class="bg-white border border-pink-100/80 rounded-2xl shadow-xs overflow-hidden">
            <div class="overflow-x-auto w-full">
              <table class="w-full min-w-[850px] text-left text-xs text-slate-700">
                <thead class="bg-pink-50/50 border-b border-pink-100 text-slate-600 font-bold uppercase text-[10px] tracking-wider">
                  <tr>
                    <th class="px-4 py-3 whitespace-nowrap">Policy</th>
                    <th class="px-4 py-3 whitespace-nowrap">Framework Control</th>
                    <th class="px-4 py-3 whitespace-nowrap">Mapping Status</th>
                    <th class="px-4 py-3 whitespace-nowrap">Confidence</th>
                    <th class="px-4 py-3">Rationale & Audit</th>
                    <th class="px-4 py-3 text-right whitespace-nowrap">Actions</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100">"""

assert old_table2 in content, "old_table2 assertion failed"
content = content.replace(old_table2, new_table2, 1)

# Close Table 2 inner div
old_table2_close = """              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    function setMappingReviewFilter(val) {"""

new_table2_close = """              </tbody>
            </table>
            </div>
          </div>
        </div>
      `;
    }

    function setMappingReviewFilter(val) {"""

assert old_table2_close in content, "old_table2_close assertion failed"
content = content.replace(old_table2_close, new_table2_close, 1)

# 10. Table 3: Framework Comparison Table in renderCoverageMatrixSubTab
old_table3 = """          <!-- Framework Comparison Table -->
          <div class="bg-white border border-pink-100/80 rounded-2xl overflow-hidden shadow-xs">
            <div class="px-5 py-4 border-b border-pink-100 flex items-center justify-between">
              <div>
                <h3 class="text-sm font-bold text-slate-900">Framework Control Breakdown</h3>
                <p class="text-xs text-slate-500 mt-0.5">Authoritative control counts and mapping coverage status by compliance standard.</p>
              </div>
            </div>
            <table class="w-full text-left text-xs text-slate-700">"""

new_table3 = """          <!-- Framework Comparison Table -->
          <div class="bg-white border border-pink-100/80 rounded-2xl shadow-xs overflow-hidden">
            <div class="px-5 py-4 border-b border-pink-100 flex items-center justify-between">
              <div>
                <h3 class="text-sm font-bold text-slate-900">Framework Control Breakdown</h3>
                <p class="text-xs text-slate-500 mt-0.5">Authoritative control counts and mapping coverage status by compliance standard.</p>
              </div>
            </div>
            <div class="overflow-x-auto w-full">
              <table class="w-full min-w-[750px] text-left text-xs text-slate-700">"""

assert old_table3 in content, "old_table3 assertion failed"
content = content.replace(old_table3, new_table3, 1)

old_table3_close = """              </tbody>
            </table>
          </div>

          <!-- Traceability Explorer: Deep Dives -->"""

new_table3_close = """              </tbody>
            </table>
            </div>
          </div>

          <!-- Traceability Explorer: Deep Dives -->"""

assert old_table3_close in content, "old_table3_close assertion failed"
content = content.replace(old_table3_close, new_table3_close, 1)

# 11. Table 4: Policy detail modal linked controls
old_table4 = """            <div class="border border-slate-200 rounded-xl overflow-hidden">
              <table class="w-full text-left text-xs text-slate-700">"""

new_table4 = """            <div class="border border-slate-200 rounded-xl shadow-2xs overflow-hidden">
              <div class="overflow-x-auto w-full">
                <table class="w-full min-w-[500px] text-left text-xs text-slate-700">"""

assert old_table4 in content, "old_table4 assertion failed"
content = content.replace(old_table4, new_table4, 1)

old_table4_close = """                  }).join('') || '<tr><td colspan="5" class="p-6 text-center text-slate-400">No framework controls currently mapped to this policy.</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>

          <!-- Modal Footer Actions -->"""

new_table4_close = """                  }).join('') || '<tr><td colspan="5" class="p-6 text-center text-slate-400">No framework controls currently mapped to this policy.</td></tr>'}
                </tbody>
              </table>
              </div>
            </div>
          </div>

          <!-- Modal Footer Actions -->"""

assert old_table4_close in content, "old_table4_close assertion failed"
content = content.replace(old_table4_close, new_table4_close, 1)

# 12. Table 5 & 6: Evidence & Assessments tables
old_table5 = """            <!-- Evidence Table -->
            <div class="bg-white border border-pink-100/80 rounded-2xl overflow-hidden shadow-xs">
              <table class="w-full text-left text-xs text-slate-700">"""

new_table5 = """            <!-- Evidence Table -->
            <div class="bg-white border border-pink-100/80 rounded-2xl shadow-xs overflow-hidden">
              <div class="overflow-x-auto w-full">
                <table class="w-full min-w-[750px] text-left text-xs text-slate-700">"""

assert old_table5 in content, "old_table5 assertion failed"
content = content.replace(old_table5, new_table5, 1)

old_table5_close = """                </tbody>
              </table>
            </div>
          </div>
        `;
      } else {
        // Tab 2: Assessment Run History
        container.innerHTML = `
          <div class="space-y-4">
            <div class="bg-white border border-pink-100/80 rounded-2xl overflow-hidden shadow-xs">
              <table class="w-full text-left text-xs text-slate-700">"""

new_table5_close = """                </tbody>
              </table>
              </div>
            </div>
          </div>
        `;
      } else {
        // Tab 2: Assessment Run History
        container.innerHTML = `
          <div class="space-y-4">
            <div class="bg-white border border-pink-100/80 rounded-2xl shadow-xs overflow-hidden">
              <div class="overflow-x-auto w-full">
                <table class="w-full min-w-[700px] text-left text-xs text-slate-700">"""

assert old_table5_close in content, "old_table5_close assertion failed"
content = content.replace(old_table5_close, new_table5_close, 1)

old_table6_close = """                </tbody>
              </table>
            </div>
          </div>
        `;
      }
    }

    async function verifyFullLedger() {"""

new_table6_close = """                </tbody>
              </table>
              </div>
            </div>
          </div>
        `;
      }
    }

    async function verifyFullLedger() {"""

assert old_table6_close in content, "old_table6_close assertion failed"
content = content.replace(old_table6_close, new_table6_close, 1)

# 13. Table 7: Findings table
old_table7 = """          <div class="bg-white border border-pink-100/80 rounded-2xl overflow-hidden shadow-xs">
            <table class="w-full text-left text-xs text-slate-700">"""

new_table7 = """          <div class="bg-white border border-pink-100/80 rounded-2xl shadow-xs overflow-hidden">
            <div class="overflow-x-auto w-full">
              <table class="w-full min-w-[800px] text-left text-xs text-slate-700">"""

assert old_table7 in content, "old_table7 assertion failed"
content = content.replace(old_table7, new_table7, 1)

old_table7_close = """                `).join('') || '<tr><td colspan="6" class="p-8 text-center text-slate-500">No security findings recorded.</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    async function advanceFindingStatus(id, currentStatus) {"""

new_table7_close = """                `).join('') || '<tr><td colspan="6" class="p-8 text-center text-slate-500">No security findings recorded.</td></tr>'}
              </tbody>
            </table>
            </div>
          </div>
        </div>
      `;
    }

    async function advanceFindingStatus(id, currentStatus) {"""

assert old_table7_close in content, "old_table7_close assertion failed"
content = content.replace(old_table7_close, new_table7_close, 1)

# 14. Pill containers wrapping
old_pills1 = '<div class="flex items-center space-x-1.5 bg-white border border-pink-100 p-1 rounded-xl shadow-2xs text-xs">'
assert old_pills1 in content, "old_pills1 assertion failed"
content = content.replace(old_pills1, '<div class="flex flex-wrap items-center gap-1.5 bg-white border border-pink-100 p-1 rounded-xl shadow-2xs text-xs">')

# 15. Hash navigation and scroll reset in navigate() and init()
old_navigate = """    function navigate(viewName) {
      currentView = viewName;
      document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.remove('bg-pink-50', 'text-pink-700', 'font-semibold', 'border-l-4', 'border-pink-600');
        el.classList.add('text-slate-600');
      });
      const activeBtn = document.getElementById(`nav-${viewName}`);
      if (activeBtn) {
        activeBtn.classList.remove('text-slate-600');
        activeBtn.classList.add('bg-pink-50', 'text-pink-700', 'font-semibold', 'border-l-4', 'border-pink-600');
      }

      const container = document.getElementById('content-container');
      const breadcrumb = document.getElementById('page-breadcrumb');"""

new_navigate = """    function navigate(viewName) {
      currentView = viewName;
      if (window.location.hash !== `#${viewName}`) {
        history.replaceState(null, '', `#${viewName}`);
      }
      const scrollViewport = document.getElementById('main-scroll-viewport');
      if (scrollViewport) scrollViewport.scrollTop = 0;

      document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.remove('bg-pink-50', 'text-pink-700', 'font-semibold', 'border-l-4', 'border-pink-600');
        el.classList.add('text-slate-600');
      });
      const activeBtn = document.getElementById(`nav-${viewName}`);
      if (activeBtn) {
        activeBtn.classList.remove('text-slate-600');
        activeBtn.classList.add('bg-pink-50', 'text-pink-700', 'font-semibold', 'border-l-4', 'border-pink-600');
      }

      const container = document.getElementById('content-container');
      const breadcrumb = document.getElementById('page-breadcrumb');"""

assert old_navigate in content, "old_navigate assertion failed"
content = content.replace(old_navigate, new_navigate, 1)

# In switchMappingsSubTab, scroll reset
old_subtab_switch = """    function switchMappingsSubTab(tab) {
      activeMappingsSubTab = tab;
      renderPoliciesAndMappings(document.getElementById('content-container'));
    }"""

new_subtab_switch = """    function switchMappingsSubTab(tab) {
      activeMappingsSubTab = tab;
      const scrollViewport = document.getElementById('main-scroll-viewport');
      if (scrollViewport) scrollViewport.scrollTop = 0;
      renderPoliciesAndMappings(document.getElementById('content-container'));
    }"""

assert old_subtab_switch in content, "old_subtab_switch assertion failed"
content = content.replace(old_subtab_switch, new_subtab_switch, 1)

# In init()
old_init = """    async function init() {
      await refreshAllData();
      navigate('overview');
    }"""

new_init = """    async function init() {
      await refreshAllData();
      const validViews = ['overview', 'controls', 'mappings', 'evidence', 'findings', 'chaos'];
      const hashView = window.location.hash.replace('#', '');
      navigate(validViews.includes(hashView) ? hashView : 'overview');
    }

    window.addEventListener('hashchange', () => {
      const hashView = window.location.hash.replace('#', '');
      if (['overview', 'controls', 'mappings', 'evidence', 'findings', 'chaos'].includes(hashView) && hashView !== currentView) {
        navigate(hashView);
      }
    });"""

assert old_init in content, "old_init assertion failed"
content = content.replace(old_init, new_init, 1)

# Write out the modified content
with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("[+] Successfully updated backend/app/static/index.html with full scrolling hierarchy and responsive table wrappers!")
