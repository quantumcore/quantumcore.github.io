document.addEventListener('DOMContentLoaded', function () {
  highlightActiveNav();
  initMobileSidebar();
  initTabs();
  initCollapsibles();
  initToasts();
  initModals();
});

function highlightActiveNav() {
  var currentPath = window.location.pathname.replace(/\/$/, '') || '/';
  var navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(function (item) {
    var href = item.getAttribute('href').replace(/\/$/, '') || '/';
    if (href === currentPath) {
      item.classList.add('active');
    }
  });
}

function initMobileSidebar() {
  var toggle = document.getElementById('sidebarToggle');
  var sidebar = document.getElementById('sidebar');
  if (!toggle || !sidebar) return;

  toggle.addEventListener('click', function (e) {
    e.stopPropagation();
    sidebar.classList.toggle('open');
  });

  document.addEventListener('click', function (e) {
    if (sidebar.classList.contains('open') &&
        !sidebar.contains(e.target) &&
        !toggle.contains(e.target) &&
        window.innerWidth <= 768) {
      sidebar.classList.remove('open');
    }
  });
}

function initTabs() {
  var tabGroups = document.querySelectorAll('.tabs');
  tabGroups.forEach(function (group) {
    var btns = group.querySelectorAll('.tab-btn');
    var panels = group.querySelectorAll('.tab-panel');

    btns.forEach(function (btn) {
      btn.addEventListener('click', function () {
        var target = btn.getAttribute('data-tab');

        btns.forEach(function (b) { b.classList.remove('active'); });
        panels.forEach(function (p) { p.classList.remove('active'); });

        btn.classList.add('active');
        var panel = document.getElementById(target);
        if (panel) panel.classList.add('active');
      });
    });
  });
}

function initCollapsibles() {
  var triggers = document.querySelectorAll('.collapsible-trigger');
  triggers.forEach(function (trigger) {
    trigger.addEventListener('click', function () {
      var parent = trigger.closest('.collapsible');
      if (parent) {
        parent.classList.toggle('open');
      }
    });
  });
}

function initToasts() {
  var toasts = document.querySelectorAll('.toast');
  toasts.forEach(function (toast) {
    setTimeout(function () {
      toast.style.animation = 'toastSlideOut 0.3s ease-in forwards';
      setTimeout(function () { toast.remove(); }, 300);
    }, 4000);
  });
}

function initModals() {
  var overlays = document.querySelectorAll('.modal-overlay');
  overlays.forEach(function (overlay) {
    var closeBtn = overlay.querySelector('.modal-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', function () {
        overlay.classList.remove('active');
      });
    }
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) {
        overlay.classList.remove('active');
      }
    });
  });
}

var Toast = {
  container: null,

  init: function () {
    this.container = document.getElementById('toast-container');
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.id = 'toast-container';
      this.container.className = 'toast-container';
      document.body.appendChild(this.container);
    }
  },

  show: function (message, type, duration) {
    if (!this.container) this.init();
    type = type || 'info';
    duration = duration || 4000;

    var toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = message;
    this.container.appendChild(toast);

    setTimeout(function () {
      toast.style.animation = 'toastSlideOut 0.3s ease-in forwards';
      setTimeout(function () { toast.remove(); }, 300);
    }, duration);
  },

  success: function (msg, d) { this.show(msg, 'success', d); },
  error: function (msg, d) { this.show(msg, 'error', d); },
  info: function (msg, d) { this.show(msg, 'info', d); }
};

var App = {
  showPage: function (pageId) {
    var pages = document.querySelectorAll('.page-section');
    pages.forEach(function (p) { p.style.display = 'none'; });
    var target = document.getElementById(pageId);
    if (target) target.style.display = 'block';

    var navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(function (item) {
      item.classList.remove('active');
      if (item.getAttribute('data-page') === pageId) {
        item.classList.add('active');
      }
    });
  }
};
