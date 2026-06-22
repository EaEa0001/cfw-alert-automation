/* 简洁线性图标集（几何线条，stroke 跟随 currentColor） */
window.CFW = window.CFW || {};
(function () {
  const S = (inner, sw = 1.6) =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;

  CFW.ICON = {
    shield: S('<path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/>'),
    grid:   S('<rect x="3.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.2"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.2"/>'),
    flow:   S('<circle cx="6" cy="6" r="2.4"/><circle cx="18" cy="6" r="2.4"/><circle cx="12" cy="18" r="2.4"/><path d="M8.4 6H15.6M6 8.4V13a2 2 0 0 0 2 2h2.2M18 8.4V13a2 2 0 0 1-2 2h-2.2"/>'),
    target: S('<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="1"/>'),
    list:   S('<path d="M8 6h12M8 12h12M8 18h12"/><circle cx="4" cy="6" r="1"/><circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/>'),
    chart:  S('<path d="M4 20V4M4 20h16"/><rect x="7" y="12" width="3" height="5"/><rect x="12.5" y="8" width="3" height="9"/><rect x="18" y="14" width="3" height="3"/>'),
    collect: S('<path d="M4 7c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z"/><path d="M4 7v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>'),
    filter: S('<path d="M4 5h16l-6 7v6l-4 2v-8L4 5z"/>'),
    funnel: S('<path d="M4 5h16M6.5 9h11M9 13h6M10.5 17h3"/>'),
    auto:   S('<circle cx="12" cy="12" r="3"/><path d="M12 4v2M12 18v2M4 12h2M18 12h2M6.3 6.3l1.4 1.4M16.3 16.3l1.4 1.4M17.7 6.3l-1.4 1.4M7.7 16.3l-1.4 1.4"/>'),
    notify: S('<path d="M6 9a6 6 0 0 1 12 0c0 5 2 6 2 6H4s2-1 2-6z"/><path d="M10 19a2 2 0 0 0 4 0"/>'),
    report: S('<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h4"/>'),
    bolt:   S('<path d="M13 3L5 13h6l-1 8 8-10h-6l1-8z"/>'),
    clock:  S('<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>'),
    eye:    S('<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>'),
    cpu:    S('<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3v2M14 3v2M10 19v2M14 19v2M3 10h2M3 14h2M19 10h2M19 14h2"/>'),
    skull:  S('<path d="M12 3a8 8 0 0 0-8 8c0 2.5 1.3 4 3 5v3h10v-3c1.7-1 3-2.5 3-5a8 8 0 0 0-8-8z"/><circle cx="9" cy="11" r="1.3"/><circle cx="15" cy="11" r="1.3"/>'),
    skip:   S('<path d="M5 5l9 7-9 7V5zM19 5v14"/>'),
    coins:  S('<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/>')
  };
})();
