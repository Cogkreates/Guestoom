/**
 * Guestoom Analytics Tracker v2.0
 * Cookieless · Privacy-first · GDPR compliant · <6KB
 *
 * Usage:
 *   <script src="https://cdn.guestoom.com/tracker.js" data-token="TOKEN" async></script>
 *
 * Optional attributes:
 *   data-server="https://your-server.com"   (if self-hosting)
 *   data-ignore="/admin,/preview"            (comma-separated paths to skip)
 */

(function () {
  "use strict";

  // ── Config ──────────────────────────────────────────────────────────────
  var el     = document.currentScript || document.querySelector("script[data-token]");
  var TOKEN  = el && el.getAttribute("data-token");
  var SERVER = (el && el.getAttribute("data-server")) || "https://api.guestoom.com";
  var IGNORE = ((el && el.getAttribute("data-ignore")) || "").split(",").map(function(s){ return s.trim(); });

  if (!TOKEN) { console.warn("[Guestoom] No data-token. Tracking disabled."); return; }

  // Respect Do Not Track
  if (navigator.doNotTrack === "1" || window.doNotTrack === "1") return;

  // ── State ────────────────────────────────────────────────────────────────
  var pageStart   = Date.now();
  var maxScroll   = 0;
  var lastPath    = location.pathname;
  var queue       = [];
  var flushTimer  = null;

  // ── Core send (batched via queue, uses sendBeacon on unload) ─────────────
  function send(payload, urgent) {
    payload.token = TOKEN;
    payload.path  = payload.path || location.pathname;
    payload.referrer = document.referrer || "";

    if (urgent && navigator.sendBeacon) {
      navigator.sendBeacon(SERVER + "/track", JSON.stringify(payload));
      return;
    }

    queue.push(payload);
    if (!flushTimer) {
      flushTimer = setTimeout(flush, 300);
    }
  }

  function flush() {
    flushTimer = null;
    if (!queue.length) return;
    var batch = queue.splice(0);
    // Send each event (extend to batch endpoint in future)
    batch.forEach(function(p) {
      if (navigator.sendBeacon) {
        navigator.sendBeacon(SERVER + "/track", JSON.stringify(p));
      } else {
        try {
          var xhr = new XMLHttpRequest();
          xhr.open("POST", SERVER + "/track", true);
          xhr.setRequestHeader("Content-Type", "application/json");
          xhr.send(JSON.stringify(p));
        } catch(e) {}
      }
    });
  }

  // ── Scroll tracking ───────────────────────────────────────────────────────
  function updateScroll() {
    var el   = document.documentElement;
    var body = document.body;
    var scrollTop  = el.scrollTop || body.scrollTop;
    var scrollH    = (el.scrollHeight || body.scrollHeight) - el.clientHeight;
    var pct = scrollH > 0 ? Math.round((scrollTop / scrollH) * 100) : 100;
    if (pct > maxScroll) maxScroll = pct;
  }

  // Throttled scroll listener
  var scrollTick = false;
  window.addEventListener("scroll", function() {
    if (!scrollTick) {
      scrollTick = true;
      setTimeout(function() { updateScroll(); scrollTick = false; }, 200);
    }
  }, { passive: true });

  // ── Click tracking (heatmap + element labels) ─────────────────────────────
  document.addEventListener("click", function(e) {
    if (isIgnored()) return;

    // Heatmap coordinates as % of viewport
    var cx = e.clientX != null ? parseFloat(((e.clientX / window.innerWidth)  * 100).toFixed(1)) : null;
    var cy = e.clientY != null ? parseFloat(((e.clientY / window.innerHeight) * 100).toFixed(1)) : null;

    // Find meaningful element label (walk up 5 levels)
    var target = e.target;
    var label  = "";
    for (var i = 0; i < 5; i++) {
      if (!target) break;
      var tag = (target.tagName || "").toLowerCase();
      if (["a","button","input","select","textarea"].indexOf(tag) > -1 || target.getAttribute("data-track")) {
        label = (
          target.getAttribute("data-track") ||
          target.getAttribute("aria-label") ||
          target.getAttribute("title") ||
          target.innerText ||
          target.getAttribute("href") ||
          target.getAttribute("name") ||
          tag
        );
        break;
      }
      target = target.parentElement;
    }

    label = (label || "").toString().replace(/\s+/g, " ").trim().slice(0, 100);

    send({
      type:    "click",
      element: label,
      cx:      cx,
      cy:      cy,
      vw:      window.innerWidth,
      vh:      window.innerHeight,
    });
  }, { passive: true });

  // ── Page leave (duration + scroll) ───────────────────────────────────────
  function trackLeave(urgent) {
    if (isIgnored()) return;
    updateScroll();
    send({
      type:       "leave",
      duration:   Math.round((Date.now() - pageStart) / 1000),
      scroll_pct: maxScroll,
    }, urgent || false);
  }

  // ── Page view ─────────────────────────────────────────────────────────────
  function trackPageview() {
    if (isIgnored()) return;
    pageStart  = Date.now();
    maxScroll  = 0;
    send({ type: "pageview" });
  }

  // ── SPA navigation (React, Vue, Next, Nuxt…) ─────────────────────────────
  function onNav() {
    var newPath = location.pathname;
    if (newPath !== lastPath) {
      trackLeave(false);
      lastPath = newPath;
      setTimeout(trackPageview, 0);
    }
  }

  // Patch History API
  ["pushState", "replaceState"].forEach(function(method) {
    var orig = history[method];
    history[method] = function() {
      orig.apply(this, arguments);
      onNav();
    };
  });
  window.addEventListener("popstate", onNav);

  // ── Ignore list ───────────────────────────────────────────────────────────
  function isIgnored() {
    var p = location.pathname;
    return IGNORE.some(function(ig) { return ig && p.indexOf(ig) === 0; });
  }

  // ── Boot ──────────────────────────────────────────────────────────────────
  function boot() {
    trackPageview();

    // Leave events — use both for coverage
    window.addEventListener("beforeunload", function() { trackLeave(true); flush(); });
    document.addEventListener("visibilitychange", function() {
      if (document.visibilityState === "hidden") { trackLeave(true); flush(); }
    });

    // Periodic scroll update
    setInterval(updateScroll, 5000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  // ── Public API (optional manual tracking) ─────────────────────────────────
  window.guestoom = {
    /**
     * Track a custom event
     * Usage: guestoom.track("Clicked CTA", { plan: "pro" })
     */
    track: function(name, meta) {
      send({
        type:    "click",
        element: name,
        cx:      null,
        cy:      null,
      });
    },
    /**
     * Mark a conversion goal
     * Usage: guestoom.goal("Signup Complete")
     */
    goal: function(name) {
      send({ type: "goal", element: name });
    },
  };

})();
