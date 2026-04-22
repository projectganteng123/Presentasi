/* ════════════════════════════════════════════════════════════════
   SimpleCipher v3 — Portfolio Script
   ════════════════════════════════════════════════════════════════ */

'use strict';

// ── Init highlight.js ────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  hljs.highlightAll();
  initNav();
  initTabs();
  initScrollReveal();
  initNavHighlight();
  initMockupAnimation();
  addMobileDataLabels();
});

// ── Navbar mobile toggle ─────────────────────────────────────────
function initNav() {
  const toggle = document.getElementById('navToggle');
  const links  = document.getElementById('navLinks');
  if (!toggle || !links) return;

  toggle.addEventListener('click', () => {
    const open = links.classList.toggle('open');
    toggle.setAttribute('aria-expanded', open);
    // Animate hamburger → X
    const spans = toggle.querySelectorAll('span');
    if (open) {
      spans[0].style.transform = 'translateY(7px) rotate(45deg)';
      spans[1].style.opacity   = '0';
      spans[2].style.transform = 'translateY(-7px) rotate(-45deg)';
    } else {
      spans.forEach(s => { s.style.transform = ''; s.style.opacity = ''; });
    }
  });

  // Close on link click
  links.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', () => {
      links.classList.remove('open');
      const spans = toggle.querySelectorAll('span');
      spans.forEach(s => { s.style.transform = ''; s.style.opacity = ''; });
    });
  });

  // Close on outside click
  document.addEventListener('click', (e) => {
    if (!toggle.contains(e.target) && !links.contains(e.target)) {
      links.classList.remove('open');
    }
  });
}

// ── Active nav highlight on scroll ──────────────────────────────
function initNavHighlight() {
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-links a');
  const navbar   = document.getElementById('navbar');

  const onScroll = () => {
    // Navbar background opacity
    if (window.scrollY > 50) {
      navbar.style.background = 'rgba(13,17,23,.97)';
    } else {
      navbar.style.background = '';
    }

    // Active section highlight
    let current = '';
    sections.forEach(sec => {
      const top = sec.offsetTop - 90;
      if (window.scrollY >= top) current = sec.id;
    });

    navLinks.forEach(a => {
      a.classList.remove('active');
      if (a.getAttribute('href') === '#' + current) {
        a.classList.add('active');
      }
    });
  };

  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
}

// ── Tab panels (6 Ronde section) ────────────────────────────────
function initTabs() {
  const tabBtns   = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;

      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanels.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const panel = document.getElementById('tab-' + target);
      if (panel) {
        panel.classList.add('active');
        // Re-highlight code in newly shown panel
        panel.querySelectorAll('pre code').forEach(el => {
          if (!el.dataset.highlighted) hljs.highlightElement(el);
        });
      }
    });
  });
}

// ── Scroll reveal ────────────────────────────────────────────────
function initScrollReveal() {
  // Add reveal class to target elements
  const targets = [
    '.problem-card',
    '.flow-step',
    '.ds-step',
    '.test-card',
    '.ui-feature-item',
    '.round-summary',
  ];

  targets.forEach(sel => {
    document.querySelectorAll(sel).forEach((el, i) => {
      el.classList.add('reveal');
      el.style.transitionDelay = (i * 0.07) + 's';
    });
  });

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
}

// ── Mock progress bar animation ──────────────────────────────────
function initMockupAnimation() {
  const bar = document.querySelector('.mpb-fill');
  const txt = document.querySelector('.mock-progress-text');
  if (!bar || !txt) return;

  let pct = 72;
  let dir = 1;
  let animating = false;

  // Start animation when mockup is visible
  const mockup = document.querySelector('.ui-mockup');
  if (!mockup) return;

  const obs = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting && !animating) {
      animating = true;
      animateBar();
    }
  }, { threshold: 0.3 });
  obs.observe(mockup);

  function animateBar() {
    const totalMB = 20.2;
    const step = () => {
      pct += dir * 0.4;
      if (pct >= 100) { pct = 100; dir = 0; }
      bar.style.width = pct + '%';
      const done = (pct / 100 * totalMB).toFixed(1);
      txt.textContent = `Enkripsi... ${Math.round(pct)}%  (${done} MB / ${totalMB} MB)`;
      if (pct < 100) requestAnimationFrame(step);
      else {
        setTimeout(() => {
          bar.style.width = '0%';
          txt.textContent = 'Siap untuk enkripsi berikutnya.';
          pct = 0;
          setTimeout(animateBar, 1200);
        }, 1500);
      }
    };
    requestAnimationFrame(step);
  }
}

// ── Add data-label attrs to features table for mobile ───────────
function addMobileDataLabels() {
  const table = document.querySelector('.features-table');
  if (!table) return;

  const headers = Array.from(table.querySelectorAll('thead th'))
                       .map(th => th.textContent.trim());

  table.querySelectorAll('tbody tr').forEach(row => {
    row.querySelectorAll('td').forEach((td, i) => {
      if (headers[i]) td.setAttribute('data-label', headers[i]);
    });
  });
}

// ── Smooth scroll offset fix for anchor links ────────────────────
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    const target = document.querySelector(this.getAttribute('href'));
    if (!target) return;
    e.preventDefault();
    const offset = parseInt(
      getComputedStyle(document.documentElement).getPropertyValue('--nav-h')
    ) || 64;
    const top = target.getBoundingClientRect().top + window.pageYOffset - offset;
    window.scrollTo({ top, behavior: 'smooth' });
  });
});
