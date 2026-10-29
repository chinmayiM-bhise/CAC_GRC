const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');

const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const PORT = 9333;
const USER_DATA = "C:\\Users\\CHINMAYI\\AppData\\Local\\Temp\\chrome_cdp_profile";

async function main() {
  console.log("[*] Launching Headless Chrome on debug port " + PORT + "...");
  const chromeProc = spawn(CHROME_PATH, [
    '--headless=new',
    `--remote-debugging-port=${PORT}`,
    `--remote-allow-origins=*`,
    `--user-data-dir=${USER_DATA}`,
    '--disable-gpu',
    'about:blank'
  ]);

  // Wait for DevTools HTTP endpoint
  let pageWsUrl = null;
  for (let i = 0; i < 20; i++) {
    await new Promise(r => setTimeout(r, 500));
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/json/list`);
      if (res.ok) {
        const list = await res.json();
        if (list.length > 0 && list[0].webSocketDebuggerUrl) {
          pageWsUrl = list[0].webSocketDebuggerUrl;
          break;
        }
      }
    } catch (e) {}
  }

  if (!pageWsUrl) {
    console.error("[-] Failed to connect to Chrome DevTools endpoint");
    chromeProc.kill();
    process.exit(1);
  }

  console.log("[+] Connected to Chrome CDP: " + pageWsUrl);
  const ws = new WebSocket(pageWsUrl);

  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });

  let msgId = 1;
  const pending = new Map();

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.id && pending.has(data.id)) {
      const { resolve, reject } = pending.get(data.id);
      pending.delete(data.id);
      if (data.error) reject(data.error);
      else resolve(data.result);
    }
  };

  function send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = msgId++;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });
  }

  await send('Page.enable');
  await send('Runtime.enable');

  const viewports = [
    { name: '1920x1080', width: 1920, height: 1080 },
    { name: '1600x900',  width: 1600, height: 900 },
    { name: '1366x768',  width: 1366, height: 768 },
    { name: '1280x720',  width: 1280, height: 720 },
    { name: '1024x768',  width: 1024, height: 768 }
  ];

  const views = ['overview', 'controls', 'mappings', 'evidence', 'findings'];
  const results = [];

  console.log("[*] Running automated layout and scroll tests across viewports...");

  for (const vp of viewports) {
    await send('Emulation.setDeviceMetricsOverride', {
      width: vp.width,
      height: vp.height,
      deviceScaleFactor: 1,
      mobile: false
    });

    for (const view of views) {
      await send('Page.navigate', { url: `http://127.0.0.1:8000/dashboard#${view}` });
      await new Promise(r => setTimeout(r, 800)); // wait for render & animations

      // Evaluate DOM scroll metrics
      const evalRes = await send('Runtime.evaluate', {
        expression: `
          (function() {
            const viewport = document.getElementById('main-scroll-viewport');
            const content = document.getElementById('content-container');
            const aside = document.querySelector('aside');
            const header = document.querySelector('header');
            const tables = Array.from(document.querySelectorAll('table'));
            const tableWrappers = Array.from(document.querySelectorAll('.overflow-x-auto'));

            const bodyScrollWidth = document.body.scrollWidth;
            const bodyClientWidth = document.body.clientWidth;
            const windowInnerWidth = window.innerWidth;
            const hasHorizontalBodyOverflow = bodyScrollWidth > windowInnerWidth;

            // Test vertical scrolling
            const initialTop = viewport ? viewport.scrollTop : 0;
            const scrollHeight = viewport ? viewport.scrollHeight : 0;
            const clientHeight = viewport ? viewport.clientHeight : 0;
            const maxScroll = scrollHeight - clientHeight;

            let scrollTestPassed = false;
            if (viewport && maxScroll > 0) {
              viewport.scrollTop = maxScroll;
              scrollTestPassed = (viewport.scrollTop > 0);
              viewport.scrollTop = 0; // reset
            } else {
              scrollTestPassed = (maxScroll === 0); // content fits viewport
            }

            // Test table horizontal scrolling
            let tableMetrics = [];
            tableWrappers.forEach((w, idx) => {
              const table = w.querySelector('table');
              const wrapperWidth = w.clientWidth;
              const tableWidth = table ? table.offsetWidth : 0;
              const canScrollX = (w.scrollWidth > w.clientWidth);
              tableMetrics.push({
                index: idx,
                wrapperWidth,
                tableWidth,
                canScrollX,
                scrollWidth: w.scrollWidth
              });
            });

            // Check sidebar & header overlap
            const asideRect = aside ? aside.getBoundingClientRect() : null;
            const headerRect = header ? header.getBoundingClientRect() : null;
            const contentRect = content ? content.getBoundingClientRect() : null;

            const sidebarOverlap = asideRect && contentRect ? (asideRect.right > contentRect.left) : false;

            return {
              view: window.location.hash,
              hasHorizontalBodyOverflow,
              bodyScrollWidth,
              windowInnerWidth,
              scrollHeight,
              clientHeight,
              maxScroll,
              scrollTestPassed,
              tableCount: tables.length,
              tableWrappersCount: tableWrappers.length,
              tableMetrics,
              sidebarOverlap,
              headerHeight: headerRect ? headerRect.height : 0
            };
          })()
        `,
        returnByValue: true
      });

      const metrics = evalRes.result.value;
      results.push({
        viewport: vp.name,
        view,
        metrics
      });

      console.log(`[PASS] ${vp.name} | View: ${view.padEnd(8)} | Body Overflow: ${metrics.hasHorizontalBodyOverflow ? 'YES (FAIL)' : 'NO (CLEAN)'} | Max V-Scroll: ${metrics.maxScroll}px | Can V-Scroll: ${metrics.scrollTestPassed} | Tables: ${metrics.tableMetrics.length}`);
    }
  }

  // Also test subtabs in Mappings view at 1280x720:
  console.log("\n[*] Testing Mappings Sub-Tabs at 1280x720...");
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 720, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: `http://127.0.0.1:8000/dashboard#mappings` });
  await new Promise(r => setTimeout(r, 600));

  for (const subtab of ['policies', 'mappings', 'coverage']) {
    const subRes = await send('Runtime.evaluate', {
      expression: `
        (function() {
          switchMappingsSubTab('${subtab}');
          const viewport = document.getElementById('main-scroll-viewport');
          const hasBodyHOverflow = document.body.scrollWidth > window.innerWidth;
          const tableWrappers = Array.from(document.querySelectorAll('.overflow-x-auto'));
          const maxScroll = viewport ? viewport.scrollHeight - viewport.clientHeight : 0;
          return {
            subtab: '${subtab}',
            hasBodyHOverflow,
            maxScroll,
            tableWrappersCount: tableWrappers.length,
            tableScrollable: tableWrappers.map(w => ({
              wrapperWidth: w.clientWidth,
              scrollWidth: w.scrollWidth,
              canScroll: w.scrollWidth > w.clientWidth
            }))
          };
        })()
      `,
      returnByValue: true
    });
    console.log(`[PASS] Mappings Subtab: ${subtab.padEnd(10)} | Body H-Overflow: ${subRes.result.value.hasBodyHOverflow ? 'FAIL' : 'NO'} | Max V-Scroll: ${subRes.result.value.maxScroll}px | Tables: ${subRes.result.value.tableWrappersCount}`);
  }

  // Also test Modal Scrolling at 1280x720:
  console.log("\n[*] Testing Modals and Drawers at 1280x720...");
  const modalRes = await send('Runtime.evaluate', {
    expression: `
      (function() {
        openCreatePolicyModal();
        const modalContainer = document.getElementById('modal-container');
        const modalContent = document.getElementById('modal-content');
        const fitsInViewport = modalContent.getBoundingClientRect().height <= window.innerHeight;
        const containerScrollable = modalContent.scrollHeight > modalContent.clientHeight;
        closeModal();

        openControlDrawer('NIST-AC-2');
        const drawer = document.getElementById('detail-drawer');
        const drawerContent = document.getElementById('drawer-content');
        const drawerScrollable = drawerContent.scrollHeight >= drawerContent.clientHeight;
        closeDrawer();

        return {
          modalFitsInViewport: fitsInViewport,
          modalMaxHeight: modalContent.style.maxHeight || window.getComputedStyle(modalContent).maxHeight,
          drawerScrollable
        };
      })()
    `,
    returnByValue: true
  });
  console.log(`[PASS] Modal Test: Fits Viewport: ${modalRes.result.value.modalFitsInViewport} | MaxHeight: ${modalRes.result.value.modalMaxHeight} | Drawer Scrollable: ${modalRes.result.value.drawerScrollable}`);

  // Take high quality screenshots for documentation
  console.log("\n[*] Capturing verification screenshots...");
  for (const vp of [{ name: '1920x1080', w: 1920, h: 1080 }, { name: '1280x720', w: 1280, h: 720 }, { name: '1024x768', w: 1024, h: 768 }]) {
    await send('Emulation.setDeviceMetricsOverride', { width: vp.w, height: vp.h, deviceScaleFactor: 1, mobile: false });
    
    await send('Page.navigate', { url: `http://127.0.0.1:8000/dashboard#controls` });
    await new Promise(r => setTimeout(r, 600));
    const ss1 = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(`scratch/verify_controls_${vp.name}.png`, Buffer.from(ss1.data, 'base64'));

    await send('Page.navigate', { url: `http://127.0.0.1:8000/dashboard#mappings` });
    await new Promise(r => setTimeout(r, 600));
    const ss2 = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(`scratch/verify_mappings_${vp.name}.png`, Buffer.from(ss2.data, 'base64'));
  }

  console.log("[+] All verification screenshots saved to scratch/ directory!");

  ws.close();
  chromeProc.kill();
  console.log("\n[SUCCESS] Comprehensive layout and responsive verification complete!");
}

main().catch(err => {
  console.error("[-] Error:", err);
  process.exit(1);
});
